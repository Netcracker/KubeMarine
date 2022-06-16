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

from kubemarine import yum, system, apt
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult

def enrich_inventory_associations(inventory, cluster):
    os_family = system.get_os_family(cluster)

    associations = inventory['services']['packages']['associations']
    if not associations.get(os_family):
        # already enriched
        return inventory

    os_specific_associations = deepcopy(associations[os_family])
    # Cache packages versions only if the option is set in configuration, so we replace the 'package_name' with the 'package_name_alt'
    if not cluster.inventory['services']['packages']['cache_versions']:
        for package in os_specific_associations:
            os_specific_associations[package]['package_name'] = \
                os_specific_associations[package]['package_name_alt']
    os_specific_associations['debian'] = deepcopy(associations['debian'])
    os_specific_associations['rhel'] = deepcopy(associations['rhel'])
    os_specific_associations['rhel8'] = deepcopy(associations['rhel8'])

    for association_name, properties in associations.items():
        if association_name in os_specific_associations.keys():
            for key, value in properties.items():
                os_specific_associations[association_name][key] = value

    inventory['services']['packages']['associations'] = os_specific_associations

    return inventory


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
    :param package: package name, which version should be detected (eg. 'podman' and 'containerd' without any version suggestion)
    :param warn: Suppress exception for non-found packages
    :return: NodeGroupResults with package version on each host

    Method generates different package query for different OS.

    Note: for Ubuntu/Debian some packages returns multiline results for some queries
    (for example docker-ce* returns docker-ce and docker-ce-cli).
    """

    if group.get_nodes_os() in ["rhel", "rhel8"]:
        cmd = r"rpm -q %s" % package
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W %s" % package

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

    if not packages_list:
        packages_list = []
        # packages from associations
        for association_name, associated_params in cluster.inventory['services']['packages']['associations'].items():
            # use 'package_name_alt' because it does not include version
            associated_packages = associated_params.get('package_name_alt', [])
            if isinstance(associated_packages, str):
                packages_list.append(associated_packages)
            else:
                packages_list = packages_list + associated_packages

    # dedup
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
            if "not installed" in node_detected_package or "no packages found" in node_detected_package:
                node_detected_package = f"not installed {package}"
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
        for host, packages in detected_packages_results.items():
            if '\n' in packages:
                # this is the test, when package name contains multiple names,
                # e.g. docker-ce and docker-cli for "docker-ce-*" query
                packages = packages.split('\n')
            else:
                packages = [packages]

            for pckg in packages:
                if pckg not in detected_grouped_packages:
                    detected_grouped_packages[pckg] = [host]
                else:
                    detected_grouped_packages[pckg].append(host)

        grouped_packages[queried_package] = detected_grouped_packages

    return grouped_packages
