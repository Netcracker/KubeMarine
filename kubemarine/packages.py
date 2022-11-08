# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from copy import deepcopy
from typing import List, Dict

from kubemarine import yum, apt, system
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult
from kubemarine.core.yaml_merger import default_merger


def enrich_inventory_associations(inventory, cluster: KubernetesCluster):
    os_family = cluster.get_os_family_from_new_nodes_or_final()
    # todo what if new and existing nodes have different OS family but new nodes have the same os family?
    if os_family in ('unknown', 'unsupported', 'multiple'):
        cluster.log.debug("Skip enrichment of associations as the nodes do not have single OS family")
        # Skip enrichment. Some features might not work.
        return inventory

    associations: dict = inventory['services']['packages']['associations']

    # copy associations for OS family to one level higher
    os_specific_associations = deepcopy(associations[os_family])

    # move associations for OS families as-is
    for association_name in get_associations_os_family_keys():
        os_specific_associations[association_name] = associations.pop(association_name)

    # merge remained explicitly defined package properties with priority
    default_merger.merge(os_specific_associations, associations)

    inventory['services']['packages']['associations'] = os_specific_associations

    return inventory


def remove_unused_os_family_associations(cluster: KubernetesCluster, inventory: dict):
    final_nodes = cluster.nodes['all'].get_final_nodes()
    for os_family in get_associations_os_family_keys():
        # Do not remove OS family associations section in finalized inventory if any node has this OS family, because
        # 1) the user might modified it directly and we not always enrich common associations section.
        # 2) in add_node procedure we enrich associations by new nodes only while initial nodes might have different OS.
        if final_nodes.get_subgroup_with_os(os_family).is_empty():
            del inventory['services']['packages']['associations'][os_family]

    return inventory


def get_associations_os_family_keys():
    return ['debian', 'rhel', 'rhel8']


def get_indexed_by_pure_packages_for_association(group: NodeGroup, association_name: str) -> dict:
    os_family = group.get_nodes_os()
    if os_family not in get_associations_os_family_keys():
        raise Exception('Failed to get package names for ambiguous OS family')

    if association_name in get_associations_os_family_keys():
        return {}

    associated_params = group.cluster.inventory['services']['packages']['associations'].get(association_name)
    if associated_params is None:
        raise Exception('Unsupported associated package')

    associated_packages = associated_params.get('package_name')
    if isinstance(associated_packages, str):
        associated_packages = [associated_packages]
    elif not isinstance(associated_packages, list):
        raise Exception('Unsupported associated packages object type')

    return {get_package_name(os_family, package): package for package in associated_packages}


def get_package_manager(group: NodeGroup) -> apt or yum:
    os_family = group.get_nodes_os()

    if os_family in ['rhel', 'rhel8']:
        return yum
    elif os_family == 'debian':
        return apt

    raise Exception('Failed to return package manager for unknown or multiple OS')


def ls_repofiles(group: NodeGroup, **kwargs) -> NodeGroupResult:
    return get_package_manager(group).ls_repofiles(group, **kwargs)


def backup_repo(group: NodeGroup, repo_filename="*", **kwargs) -> NodeGroupResult:
    return get_package_manager(group).backup_repo(group, repo_filename, **kwargs)


def add_repo(group: NodeGroup, repo_data="", repo_filename="predefined", **kwargs) -> NodeGroupResult:
    return get_package_manager(group).add_repo(group, repo_data, repo_filename, **kwargs)


def clean(group: NodeGroup, mode="all", **kwargs) -> NodeGroupResult:
    return get_package_manager(group).clean(group, mode, **kwargs)


def install(group: NodeGroup, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    return get_package_manager(group).install(group, include, exclude, **kwargs)


def remove(group: NodeGroup, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    return get_package_manager(group).remove(group, include, exclude, **kwargs)


def upgrade(group: NodeGroup, include=None, exclude=None, **kwargs) -> NodeGroupResult:
    return get_package_manager(group).upgrade(group, include, exclude, **kwargs)


def detect_installed_package_version(group: NodeGroup, package: str, warn=True) -> NodeGroupResult:
    """
    Detect package versions for each host on remote group
    :param group: Group of nodes, where package should be found
    :param package: package name, which version should be detected (eg. 'podman' and 'containerd')
    :param warn: Suppress exception for non-found packages
    :return: NodeGroupResults with package version on each host

    Method generates different package query for different OS.

    Note: for Ubuntu/Debian some packages returns multiline results for some queries
    (for example docker-ce* returns docker-ce and docker-ce-cli).
    """

    os_family = group.get_nodes_os()
    package_name = get_package_name(os_family, package)

    if os_family in ["rhel", "rhel8"]:
        cmd = r"rpm -q %s" % package_name
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W %s" % package_name

    # This is WA for RemoteExecutor, since any package failed others are not checked
    # TODO: get rid of this WA and use warn=True in sudo
    if warn:
        cmd += ' || true'

    return group.sudo(cmd)


def detect_installed_packages_versions(group: NodeGroup, packages_list: List or str = None) -> Dict[str, NodeGroupResult]:
    """
    Detect packages versions for each host on remote group from specified list of packages
    :param group: Group of nodes, where packages should be found
    :param packages_list: Single package or list of packages, which versions should be detected. If packages list empty,
    then packages will be automatically added from services.packages.associations and services.packages.install.include
    :return: Dictionary with NodeGroupResults for each queried package, e.g. "foo" -> {1.1.1.1:"foo-1", 1.1.1.2:"foo-2"}
    """

    cluster = group.cluster
    # todo skip detection of cache_versions=false packages from outside
    excluded_dict = {}

    if packages_list is None:
        packages_list = []
        # packages from associations
        for association_name, associated_params in cluster.inventory['services']['packages']['associations'].items():
            indexed_by_pure_packages = get_indexed_by_pure_packages_for_association(group, association_name)
            if not indexed_by_pure_packages:
                continue
            packages_list.extend(indexed_by_pure_packages.keys())
            if not associated_params.get('cache_versions', True):
                # replace packages with associated version that should be excluded from cache
                excluded_dict.update(indexed_by_pure_packages)

    # deduplicate
    packages_list = list(set(packages_list))

    with RemoteExecutor(cluster) as exe:
        for package in packages_list:
            detect_installed_package_version(group, package, warn=True)

    raw_result = exe.get_last_results()
    results: dict[str, NodeGroupResult] = {}

    for i, package in enumerate(packages_list):
        results[package] = NodeGroupResult(cluster)
        for host, multiple_results in raw_result.items():
            node_detected_package = multiple_results[i].stdout.strip() + multiple_results[i].stderr.strip()
            # consider version, which ended with special symbol = or - as not installed
            # (it is possible in some cases to receive "containerd=" version)
            if "not installed" in node_detected_package or "no packages found" in node_detected_package \
                    or node_detected_package[-1] == '=' or node_detected_package[-1] == '-':
                node_detected_package = f"not installed {package}"
            elif package in excluded_dict.keys():
                node_detected_package = excluded_dict[package]
            results[package][host] = node_detected_package

    return results


def detect_installed_packages_version_groups(group: NodeGroup, packages_list: List or str = None) \
        -> Dict[str, Dict[str, List]]:
    """
    Detect grouped packages versions on remote group from specified list of packages.
    :param group: Group of nodes, where packages should be found
    :param packages_list: Single package or list of packages, which versions should be detected. If packages list empty,
    then packages will be automatically added from services.packages.associations and services.packages.install.include
    :return: Dictionary with grouped versions for each queried package, pointing to list of hosts,
        e.g. {"foo" -> {"foo-1": [host1, host2]}, "bar" -> {"bar-1": [host1], "bar-2": [host2]}}
    """

    detected_packages = detect_installed_packages_versions(group, packages_list)
    grouped_packages: Dict[str, Dict[str, List]] = {}
    for queried_package, detected_packages_results in detected_packages.items():
        detected_grouped_packages = {}
        for host, pckg in detected_packages_results.items():
            detected_grouped_packages.setdefault(pckg, []).append(host)

        grouped_packages[queried_package] = detected_grouped_packages

    return grouped_packages


def get_package_name(os_family: str, package: str) -> str:
    """
    Return the pure package name, whithout any part of version
    """

    import re

    package_name = ""
    
    if package:
        if os_family in ["rhel", "rhel8"]:
            # regexp is needed to split package and its version, the pattern start with '-' then should be number or '*'
            package_name = re.split(r'-[\d,\*]', package)[0]
        else:
            # in ubuntu it is much easier to parse package name
            package_name = package.split("=")[0]

    return package_name
