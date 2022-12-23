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

from typing import List, Dict

from kubemarine import yum, apt
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult
from kubemarine.core.yaml_merger import default_merger


ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS = \
    "It is not supported to customize services.packages.associations section " \
    "if nodes have different OS families. " \
    "Please move the section to corresponding services.packages.associations.<os_family> section."

ERROR_MULTIPLE_PACKAGE_VERSIONS_DETECTED = \
    "Multiple package versions detected %s for package '%s'. " \
    "Align them to the single version manually or using corresponding task of install procedure. " \
    "Alternatively, specify cache_versions=false for corresponding association."


def enrich_inventory_associations(inventory, cluster: KubernetesCluster):
    associations: dict = inventory['services']['packages']['associations']
    os_propagated_associations = {}

    # move associations for OS families as-is
    for association_name in get_associations_os_family_keys():
        os_propagated_associations[association_name] = associations.pop(association_name)

    inventory['services']['packages']['associations'] = os_propagated_associations

    # Check remained associations section if they are customized at global level.
    if associations:
        os_family = cluster.get_os_family()
        if os_family == 'multiple':
            raise Exception(ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS)
        elif os_family not in ('unknown', 'unsupported'):
            # move remained associations properties to the specific OS family section and merge with priority
            default_merger.merge(os_propagated_associations[os_family], associations)

    return inventory


def cache_package_versions(cluster: KubernetesCluster, inventory: dict, ensured_associations_only=False) -> dict:
    os_ids = cluster.get_os_identifiers()
    different_os = list(set(os_ids.values()))
    if len(different_os) > 1:
        cluster.log.debug(f"Final nodes have different OS families or versions, packages will not be cached. "
                          f"List of (OS family, version): {different_os}")
        return inventory

    os_family = different_os[0][0]
    if os_family in ('unknown', 'unsupported'):
        # For add_node/install procedures we check that OS is supported in prepare.check.system task.
        # For check_iaas procedure it is allowed to have unsupported OS, so skip caching.
        cluster.log.debug("Skip caching of packages for unsupported OS.")
        return inventory

    nodes_cache_versions = cluster.nodes['all'].get_final_nodes().get_sudo_nodes()
    if nodes_cache_versions.is_empty():
        # For add_node/install procedures we check that all nodes are sudoers in prepare.check.sudoer task.
        # For check_iaas procedure the nodes might still be not sudoers, so skip caching.
        cluster.log.debug(f"There are no nodes with sudo privileges, packages will not be cached.")
        return inventory

    packages_list = _get_packages_to_detect_versions(cluster, inventory, ensured_associations_only)
    detected_packages = detect_installed_packages_version_groups(nodes_cache_versions, packages_list)

    _cache_package_associations(cluster, inventory, detected_packages, ensured_associations_only)
    _cache_custom_packages(cluster, inventory, detected_packages, ensured_associations_only)

    cluster.log.debug('Package versions detection finished')
    return inventory


def _get_associations(cluster: KubernetesCluster, inventory: dict):
    return inventory['services']['packages']['associations'][cluster.get_os_family()]


def _get_package_names_for_association(cluster: KubernetesCluster, inventory: dict, association_name: str) -> list:
    if association_name in get_associations_os_family_keys():
        return []

    associated_packages = _get_associations(cluster, inventory)[association_name].get('package_name')
    if isinstance(associated_packages, str):
        associated_packages = [associated_packages]
    elif not isinstance(associated_packages, list):
        raise Exception('Unsupported associated packages object type')

    return associated_packages


def _get_packages_for_associations_to_detect(cluster: KubernetesCluster, inventory: dict, association_name: str,
                                             ensured_association_only: bool) -> list:
    packages_list = _get_package_names_for_association(cluster, inventory, association_name)
    if not packages_list:
        return []

    global_cache_versions = inventory['services']['packages']['cache_versions']
    associated_params = _get_associations(cluster, inventory)[association_name]
    if not ensured_association_only or (global_cache_versions and associated_params.get('cache_versions', True)):
        return packages_list

    return []


def _get_packages_to_detect_versions(cluster: KubernetesCluster, inventory: dict, ensured_association_only: bool) -> list:
    packages_list = []
    for association_name in _get_associations(cluster, inventory).keys():
        packages_list.extend(_get_packages_for_associations_to_detect(
            cluster, inventory, association_name, ensured_association_only))

    if not ensured_association_only and inventory['services']['packages'].get('install', {}):
        packages_list.extend(inventory['services']['packages']['install']['include'])

    return packages_list


def _cache_package_associations(cluster: KubernetesCluster, inventory: dict,
                                detected_packages: Dict[str, Dict[str, List]], ensured_association_only: bool):
    for association_name, associated_params in _get_associations(cluster, inventory).items():
        packages_list = _get_packages_for_associations_to_detect(
            cluster, inventory, association_name, ensured_association_only)
        if not packages_list:
            continue

        final_packages_list = []
        for package in packages_list:
            final_package = _detect_final_package(cluster, detected_packages, package, ensured_association_only)
            final_packages_list.append(final_package)

        # if non-multiple value, then convert to simple string
        # packages can contain multiple package values, like docker package
        # (it has docker-ce, docker-cli and containerd.io packages for installation)
        if len(final_packages_list) == 1:
            final_packages_list = final_packages_list[0]

        associated_params['package_name'] = final_packages_list


def _cache_custom_packages(cluster: KubernetesCluster, inventory: dict,
                           detected_packages: Dict[str, Dict[str, List]], ensured_association_only: bool):
    if ensured_association_only:
        return
    # packages from direct installation section
    custom_install_packages = inventory['services']['packages'].get('install', {})
    if custom_install_packages:
        final_packages_list = []
        for package in custom_install_packages['include']:
            final_package = _detect_final_package(cluster, detected_packages, package, False)
            final_packages_list.append(final_package)
        custom_install_packages['include'] = final_packages_list
    return detected_packages


def _detect_final_package(cluster: KubernetesCluster, detected_packages: Dict[str, Dict[str, List]],
                          package: str, ensured_association_only: bool) -> str:
    # add package version to list only if it was found as installed
    detected_package_versions = list(filter(lambda version: "not installed" not in version,
                                            detected_packages[package].keys()))

    # if there no versions detected, then return default package from inventory
    if not detected_package_versions:
        return package
    elif len(detected_package_versions) > 1:
        if ensured_association_only:
            raise Exception(ERROR_MULTIPLE_PACKAGE_VERSIONS_DETECTED % (str(detected_packages[package]), package))
        else:
            cluster.log.warning(
                f"Multiple package versions detected {detected_packages[package]} for package '{package}'. "
                f"Use default package '{package}' from inventory.")
            # return default package from inventory if multiple versions detected
            return package
    else:
        return detected_package_versions[0]


def remove_unused_os_family_associations(cluster: KubernetesCluster, inventory: dict):
    final_nodes = cluster.nodes['all'].get_final_nodes()
    for os_family in get_associations_os_family_keys():
        # Do not remove OS family associations section in finalized inventory if any node has this OS family.
        if final_nodes.get_subgroup_with_os(os_family).is_empty():
            del inventory['services']['packages']['associations'][os_family]

    return inventory


def get_associations_os_family_keys():
    return {'debian', 'rhel', 'rhel8'}


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


def get_detect_package_version_cmd(os_family: str, package_name: str) -> str:
    if os_family in ["rhel", "rhel8"]:
        cmd = r"rpm -q %s" % package_name
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W %s" % package_name

    # This is WA for RemoteExecutor, since any package failed others are not checked
    # TODO: get rid of this WA and use warn=True in sudo
    cmd += ' || true'
    return cmd


def detect_installed_package_version(group: NodeGroup, package: str) -> NodeGroupResult:
    """
    Detect package versions for each host on remote group
    :param group: Group of nodes, where package should be found
    :param package: package name, which version should be detected (eg. 'podman' and 'containerd')
    :return: NodeGroupResults with package version on each host

    Method generates different package query for different OS.

    Note: for Ubuntu/Debian some packages returns multiline results for some queries
    (for example docker-ce* returns docker-ce and docker-ce-cli).
    """

    os_family = group.get_nodes_os()
    package_name = get_package_name(os_family, package)

    cmd = get_detect_package_version_cmd(os_family, package_name)
    return group.sudo(cmd)


def detect_installed_packages_version_groups(group: NodeGroup, packages_list: List or str) -> Dict[str, Dict[str, List]]:
    """
    Detect grouped packages versions on remote group from specified list of packages.
    :param group: Group of nodes, where packages should be found
    :param packages_list: Single package or list of packages, which versions should be detected.
    :return: Dictionary with grouped versions for each queried package, pointing to list of hosts,
        e.g. {"foo" -> {"foo-1": [host1, host2]}, "bar" -> {"bar-1": [host1], "bar-2": [host2]}}
    """

    cluster = group.cluster

    if isinstance(packages_list, str):
        packages_list = [packages_list]
    # deduplicate
    packages_list = list(set(packages_list))
    if not packages_list:
        return {}

    with RemoteExecutor(cluster) as exe:
        for package in packages_list:
            detect_installed_package_version(group, package)

    raw_result = exe.get_last_results()
    results: Dict[str, Dict[str, List]] = {}

    for i, package in enumerate(packages_list):
        detected_grouped_packages = {}
        for conn, multiple_results in raw_result.items():
            node_detected_package = multiple_results[i].stdout.strip() + multiple_results[i].stderr.strip()
            # consider version, which ended with special symbol = or - as not installed
            # (it is possible in some cases to receive "containerd=" version)
            if "not installed" in node_detected_package or "no packages found" in node_detected_package \
                    or node_detected_package[-1] == '=' or node_detected_package[-1] == '-':
                node_detected_package = f"not installed {package}"
            detected_grouped_packages.setdefault(node_detected_package, []).append(conn.host)

        results[package] = detected_grouped_packages

    return results


def get_package_name(os_family: str, package: str) -> str:
    """
    Return the pure package name, without any part of version
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


def search_package(group: NodeGroup, package: str, **kwargs) -> NodeGroupResult:
    return get_package_manager(group).search(group, package, **kwargs)


def create_repo_file(group: NodeGroup, repo_data, repo_file):
    get_package_manager(group).create_repo_file(group, repo_data, repo_file)


def get_repo_filename(group: NodeGroup, repo_filename="predefined"):
    return get_package_manager(group).get_repo_file_name(repo_filename)