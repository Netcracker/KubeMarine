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

import fabric

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

ERROR_SEMANAGE_NOT_MANAGED_DEBIAN = "semanage is not managed for debian OS family by KubeMarine"


def enrich_inventory_associations(inventory, cluster: KubernetesCluster):
    associations: dict = inventory['services']['packages']['associations']
    enriched_associations = {}

    # Move associations for OS families and merge with globals
    for association_name in get_associations_os_family_keys():
        os_associations: dict = deepcopy(cluster.globals['packages']['common_associations'])
        if association_name == 'debian':
            del os_associations['semanage']
        for association_params in os_associations.values():
            del association_params['groups']
        default_merger.merge(os_associations, associations.pop(association_name))
        enriched_associations[association_name] = os_associations

    # Check remained associations section if they are customized at global level.
    if associations:
        os_family = cluster.get_os_family()
        if os_family == 'multiple':
            raise Exception(ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS)
        elif os_family not in ('unknown', 'unsupported'):
            # move remained associations properties to the specific OS family section and merge with priority
            default_merger.merge(enriched_associations[os_family], associations)

    if 'semanage' in enriched_associations['debian']:
        raise Exception(ERROR_SEMANAGE_NOT_MANAGED_DEBIAN)

    inventory['services']['packages']['associations'] = enriched_associations

    return inventory


def enrich_inventory_packages(inventory: dict, _):
    for _type in ['install', 'upgrade', 'remove']:
        packages_list = inventory['services']['packages'].get(_type)
        if isinstance(packages_list, list):
            inventory['services']['packages'][_type] = {
                'include': packages_list
            }

    return inventory


def enrich_inventory_include_all(inventory: dict, _):
    for _type in ['upgrade', 'remove']:
        packages: dict = inventory['services']['packages'].get(_type)
        if packages is not None:
            packages.setdefault('include', ['*'])

    return inventory


def cache_package_versions(cluster: KubernetesCluster, inventory: dict, by_initial_nodes=False) -> dict:
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

    group = cluster.nodes['all'].get_final_nodes()
    if group.nodes_amount() != group.get_sudo_nodes().nodes_amount():
        # For add_node/install procedures we check that all nodes are sudoers in prepare.check.sudoer task.
        # For check_iaas procedure the nodes might still be not sudoers.
        # Skip caching if any not-sudoer node found.
        cluster.log.debug(f"Some nodes are not sudoers, packages will not be cached.")
        return inventory

    if by_initial_nodes:
        group = group.get_initial_nodes()

    hosts_to_packages = get_all_managed_packages_for_group(group, inventory, by_initial_nodes)
    detected_packages = detect_installed_packages_version_hosts(cluster, hosts_to_packages)

    _cache_package_associations(group, inventory, detected_packages, by_initial_nodes)
    _cache_custom_packages(cluster, inventory, detected_packages, by_initial_nodes)

    cluster.log.debug('Package versions detection finished')
    return inventory


def get_all_managed_packages_for_group(group: NodeGroup, inventory: dict, ensured_association_only: bool = False) \
        -> Dict[str, List[str]]:
    """
    Returns hosts with list of all managed packages for them.
    For associations, only subset of hosts is considered on which the associations are managed by KubeMarine.

    :param group: Group of nodes to get the manager packages for.
    :param inventory: Inventory of the cluster. May be different from the inventory of the cluster instance,
                      if used during finalization.
    :param ensured_association_only: Specify whether to take 'cache_versions' property into account for associations.
                                     Additionally, if true, will skip custom packages.
    :return: List of packages for each relevant host.
    """
    packages_section = inventory['services']['packages']
    hosts_to_packages = {}
    for node in group.get_ordered_members_list():
        os_family = node.get_nodes_os()
        node_associations = packages_section['associations'].get(os_family, {})
        for association_name in node_associations.keys():
            packages = get_association_hosts_to_packages(
                node, inventory, association_name, ensured_association_only)

            packages = next(iter(packages.values()), [])
            hosts_to_packages.setdefault(node.get_host(), []).extend(packages)

    custom_install_packages = inventory['services']['packages'].get('install', {}).get('include', [])
    if not ensured_association_only and custom_install_packages:
        for host in group.get_hosts():
            hosts_to_packages.setdefault(host, []).extend(custom_install_packages)

    return hosts_to_packages


def get_association_hosts_to_packages(group: NodeGroup, inventory: dict, association_name: str,
                                      ensured_association_only: bool = False) \
        -> Dict[str, List[str]]:
    """
    Returns hosts with associated packages list for the specified association name.
    Only subset of hosts is returned on which the association is managed by KubeMarine.

    :param group: Group of nodes to check the applicability of the association.
    :param inventory: Inventory of the cluster. May be different from the inventory of the cluster instance,
                      if used during finalization.
    :param association_name: target association name
    :param ensured_association_only: Specify whether to take 'cache_versions' property into account.
    :return: List of packages for each relevant host.
    """
    cluster = group.cluster

    packages_section = inventory['services']['packages']
    if not packages_section['mandatory'].get(association_name, True):
        return {}

    hosts_to_packages = {}

    if association_name == 'unzip':
        from kubemarine import thirdparties
        relevant_group = thirdparties.get_group_require_unzip(cluster, inventory)
    else:
        groups = cluster.globals['packages']['common_associations'].get(association_name, {}).get('groups', [])
        relevant_group = cluster.create_group_from_groups_nodes_names(groups, [])

    if association_name in ('docker', 'containerd') \
            and association_name != inventory['services']['cri']['containerRuntime']:
        relevant_group = cluster.make_group([])

    relevant_group = relevant_group.intersection_group(group)

    global_cache_versions = packages_section['cache_versions']
    for node in relevant_group.get_ordered_members_list():
        os_family = node.get_nodes_os()
        package_associations = packages_section['associations'].get(os_family, {}).get(association_name, {})
        packages = package_associations.get('package_name', [])

        if isinstance(packages, str):
            packages = [packages]

        if ensured_association_only and not (global_cache_versions and package_associations.get('cache_versions', True)):
            packages = []

        if packages:
            hosts_to_packages[node.get_host()] = packages

    return hosts_to_packages


def _cache_package_associations(group: NodeGroup, inventory: dict,
                                detected_packages: Dict[str, Dict[str, List]], ensured_association_only: bool):
    cluster = group.cluster
    associations = inventory['services']['packages']['associations'][cluster.get_os_family()]
    for association_name, associated_params in associations.items():
        hosts_to_packages = get_association_hosts_to_packages(
            group, inventory, association_name, ensured_association_only)
        if not hosts_to_packages:
            continue

        # Since all nodes have the same OS family in this case,
        # the packages list is the same for all relevant hosts, so take any available.
        packages_list = next(iter(hosts_to_packages.values()))

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
    if custom_install_packages.get('include', []):
        final_packages_list = []
        for package in custom_install_packages['include']:
            final_package = _detect_final_package(cluster, detected_packages, package, False)
            final_packages_list.append(final_package)
        custom_install_packages['include'] = final_packages_list


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


def no_changes_found(group: NodeGroup, action: callable, result: fabric.runners.Result) -> bool:
    pkg_mgr = get_package_manager(group)
    if action is install:
        action = pkg_mgr.install
    elif action is upgrade:
        action = pkg_mgr.upgrade
    elif action is remove:
        action = pkg_mgr.remove
    return pkg_mgr.no_changes_found(action, result)


def get_detect_package_version_cmd(os_family: str, package_name: str) -> str:
    if os_family in ["rhel", "rhel8"]:
        cmd = r"rpm -q %s" % package_name
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W %s" % package_name

    # This is WA for RemoteExecutor, since any package failed others are not checked
    # TODO: get rid of this WA and use warn=True in sudo
    cmd += ' || true'
    return cmd


def _detect_installed_package_version(group: NodeGroup, package: str) -> NodeGroupResult:
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


def _parse_node_detected_package(result: fabric.runners.Result, package: str) -> str:
    node_detected_package = result.stdout.strip() + result.stderr.strip()
    # consider version, which ended with special symbol = or - as not installed
    # (it is possible in some cases to receive "containerd=" version)
    if "not installed" in node_detected_package or "no packages found" in node_detected_package \
            or node_detected_package[-1] == '=' or node_detected_package[-1] == '-':
        node_detected_package = f"not installed {package}"

    return node_detected_package


def detect_installed_packages_version_hosts(cluster: KubernetesCluster, hosts_to_packages: Dict[str, List[str]]) \
        -> Dict[str, Dict[str, List]]:
    """
    Detect grouped packages versions for specified list of packages for each remote host.

    :param cluster: KubernetesCluster instance
    :param hosts_to_packages: Remote hosts with list of packages to detect versions.
    :return: Dictionary with grouped versions for each queried package, pointing to list of hosts,
        e.g. {"foo" -> {"foo-1": [host1, host2]}, "bar" -> {"bar-1": [host1], "bar-2": [host2]}}
    """
    for host, packages_list in hosts_to_packages.items():
        if isinstance(packages_list, str):
            packages_list = [packages_list]
        # deduplicate
        hosts_to_packages[host] = list(set(packages_list))

    with RemoteExecutor(cluster) as exe:
        for host, packages_list in hosts_to_packages.items():
            node = cluster.make_group([host])
            for package in packages_list:
                _detect_installed_package_version(node, package)

    raw_result = exe.get_last_results()
    if not raw_result:
        return {}

    results: Dict[str, Dict[str, List]] = {}

    for conn, multiple_results in raw_result.items():
        multiple_results = list(multiple_results.values())
        host = conn.host
        packages_list = hosts_to_packages[host]
        for i, package in enumerate(packages_list):
            node_detected_package = _parse_node_detected_package(multiple_results[i], package)
            results.setdefault(package, {}).setdefault(node_detected_package, []).append(host)

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