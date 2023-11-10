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
from typing import List, Dict, Tuple, Optional, Union, Mapping, Set

from typing_extensions import Protocol

from kubemarine import yum, apt
from kubemarine.core import errors, utils, static
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RunnersResult, Token, Callback
from kubemarine.core.group import (
    NodeGroup, DeferredGroup, AbstractGroup, RunResult, GROUP_RUN_TYPE,
    CollectorCallback, RunnersGroupResult
)
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


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    enrich_inventory_associations(inventory, cluster)
    enrich_inventory_packages(inventory, cluster)

    return inventory


def enrich_inventory_associations(inventory: dict, cluster: KubernetesCluster) -> None:
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


def enrich_inventory_packages(inventory: dict, _: KubernetesCluster) -> None:
    for _type in ['install', 'upgrade', 'remove']:
        packages_list = inventory['services']['packages'].get(_type)
        if isinstance(packages_list, list):
            inventory['services']['packages'][_type] = {
                'include': packages_list
            }


def enrich_inventory_apply_defaults(inventory: dict, _: KubernetesCluster) -> dict:
    kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']

    for os_family in get_associations_os_family_keys():
        cluster_associations = inventory["services"]["packages"]["associations"][os_family]
        for package in static.GLOBALS['packages'][os_family]:
            if cluster_associations[package].get('package_name') is None:
                cluster_associations[package]['package_name'] = \
                    get_default_package_names(os_family, package, kubernetes_version)

    return inventory


def _get_associations_upgrade_plan(cluster: KubernetesCluster, inventory: dict) -> List[Tuple[str, dict]]:
    context = cluster.context
    if context.get("initial_procedure") == "upgrade":
        upgrade_version = context["upgrade_version"]
        upgrade_plan = []
        for version in cluster.procedure_inventory['upgrade_plan']:
            if utils.version_key(version) < utils.version_key(upgrade_version):
                continue

            upgrade_associations = cluster.procedure_inventory.get(version, {}).get("packages", {}).get("associations", {})
            upgrade_associations = dict(item for item in upgrade_associations.items()
                                        if item[0] in _get_system_packages_support_upgrade(inventory))
            upgrade_plan.append((version, upgrade_associations))

    elif context.get("initial_procedure") == "migrate_kubemarine" and "upgrading_package" in context:
        upgrade_associations = cluster.procedure_inventory.get('upgrade', {}).get("packages", {}).get("associations", {})
        upgrade_associations = dict(item for item in upgrade_associations.items()
                                    if item[0] == context["upgrading_package"])
        upgrade_plan = [("", upgrade_associations)]
    else:
        upgrade_plan = []

    return upgrade_plan


def enrich_upgrade_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    upgrade_plan = _get_associations_upgrade_plan(cluster, inventory)
    if not upgrade_plan:
        return inventory

    os_family = cluster.get_os_family()
    if os_family not in get_associations_os_family_keys():
        raise errors.KME("KME0012", procedure='upgrade')

    context = cluster.context
    if context.get("initial_procedure") == "upgrade":
        previous_version = context["initial_kubernetes_version"]
        packages_verify = _get_system_packages_support_upgrade(inventory)
    else:  # migrate_kubemarine procedure
        previous_version = ""
        packages_verify = [context["upgrading_package"]]

    cluster_associations = inventory["services"]["packages"]["associations"][os_family]
    _verify_upgrade_plan(cluster_associations, previous_version, packages_verify, upgrade_plan)

    upgrade_required = get_system_packages_for_upgrade(cluster, inventory)
    context.setdefault("upgrade", {}).setdefault('required', {})['packages'] = upgrade_required

    # Merge procedure associations with the OS family specific section of associations in the inventory.
    upgrade_inventory_associations(cluster, inventory, enrich_global=False)
    upgrade_inventory_packages(cluster, inventory)

    return inventory


def upgrade_inventory_associations(cluster: KubernetesCluster, inventory: dict,
                                   *, enrich_global: bool) -> None:
    # pass enriched 'cluster.inventory' instead of 'inventory' that is being finalized
    upgrade_plan = _get_associations_upgrade_plan(cluster, cluster.inventory)
    if not upgrade_plan:
        return

    _, upgrade_associations = upgrade_plan[0]
    _enrich_inventory_procedure_associations(cluster, inventory, upgrade_associations,
                                             enrich_global=enrich_global)


def upgrade_inventory_packages(cluster: KubernetesCluster, inventory: dict) -> None:
    if cluster.context.get("initial_procedure") != "upgrade":
        return

    upgrade_version = cluster.context["upgrade_version"]
    for _type in ['install', 'upgrade', 'remove']:
        packages_section = cluster.procedure_inventory.get(upgrade_version, {}).get("packages", {})
        upgrade_packages = packages_section.get(_type)
        if upgrade_packages is None:
            continue
        if isinstance(upgrade_packages, list):
            upgrade_packages = {'include': upgrade_packages}

        packages_section = inventory.setdefault("services", {}).setdefault("packages", {})
        inventory_packages = packages_section.setdefault(_type, {})
        if isinstance(inventory_packages, list):
            packages_section[_type] = inventory_packages = {
                'include': inventory_packages
            }

        default_merger.merge(inventory_packages, upgrade_packages)


def _verify_upgrade_plan(cluster_associations: dict, previous_version: str,
                         packages_verify: List[str], upgrade_plan: List[Tuple[str, dict]]) -> None:
    cluster_associations = deepcopy(cluster_associations)

    # validate all packages sections in procedure inventory
    for version, upgrade_associations in upgrade_plan:
        for package in packages_verify:
            upgrade_package_name = upgrade_associations.get(package, {}).get('package_name')
            # Here default package names are not yet enriched and thus hold the custom supplied package names.
            if cluster_associations[package].get('package_name') and not upgrade_package_name:
                raise errors.KME("KME0010", package=package,
                                 previous_version_spec=f' for version {previous_version}' if previous_version else "",
                                 next_version_spec=f' for version {version}' if version else "")
            if upgrade_package_name:
                cluster_associations[package]['package_name'] = upgrade_package_name
        previous_version = version


def get_default_package_names(os_family: str, package: str, kubernetes_version: str) -> List[str]:
    version_key = get_compatibility_version_key(os_family)
    compatibility = static.GLOBALS['compatibility_map']['software']
    packages_names: List[Dict[str, str]] = static.GLOBALS['packages'][os_family][package]['package_name']

    package_versions = []
    for kv in packages_names:
        package_name, software_name = next((k, v) for k, v in kv.items())
        if software_name in ('haproxy', 'keepalived'):
            version = compatibility[software_name][version_key]
        else:
            version = compatibility[software_name][kubernetes_version][version_key]

        package_versions.append(f"{package_name}{get_package_version_separator(os_family)}{version}")

    return package_versions


def get_system_packages_for_upgrade(cluster: KubernetesCluster, inventory: dict) -> List[str]:
    undefined_package_name = object()

    context = cluster.context
    os_family = cluster.get_os_family()

    cluster_associations = inventory['services']['packages']['associations'][os_family]
    _, upgrade_associations = _get_associations_upgrade_plan(cluster, inventory)[0]

    # Resolve old and new packages with versions and schedule for upgrade if they are not equal.
    system_packages = _get_system_packages_support_upgrade(inventory)
    upgrade_required = []
    for package in system_packages:
        # Here default package names are not yet enriched and thus hold the custom supplied package names.
        old_package_name = cluster_associations[package].get('package_name')
        if old_package_name is None:
            # Trying enrichment before upgrade
            if context.get("initial_procedure") == "migrate_kubemarine":
                # Recommended versions have changed, and we forgot about what versions were previously recommended.
                old_package_name = undefined_package_name
            else:
                # upgrade procedure
                previous_ver = context["initial_kubernetes_version"]
                old_package_name = get_default_package_names(os_family, package, previous_ver)

        new_package_name = cluster_associations[package].get('package_name')
        # associations from procedure inventory have priority
        upgrade_package_name = upgrade_associations.get(package, {}).get('package_name')
        if upgrade_package_name:
            new_package_name = upgrade_package_name
        if new_package_name is None:
            # For upgrade procedure, services.kubeadm.kubernetesVersion is equal to 'upgrade_version',
            # because the version was already enriched.
            upgrade_ver = inventory['services']['kubeadm']['kubernetesVersion']
            new_package_name = get_default_package_names(os_family, package, upgrade_ver)

        if old_package_name is undefined_package_name or old_package_name != new_package_name:
            upgrade_required.append(package)

    return upgrade_required


def _get_system_packages_support_upgrade(inventory: dict) -> List[str]:
    return [inventory['services']['cri']['containerRuntime'], 'haproxy', 'keepalived']


def enrich_migrate_cri_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory

    os_family = cluster.get_os_family()
    if os_family not in get_associations_os_family_keys():
        raise errors.KME("KME0012", procedure='migrate_cri')

    procedure_associations = cluster.procedure_inventory.get("packages", {}).get("associations", {})
    # Merge OS family specific section. It is already enriched in enrich_inventory_associations()
    # This effectively allows to specify only global section but not for specific OS family.
    # This restriction is because enrich_migrate_cri_inventory() goes after enrich_inventory_associations(),
    # but in future the restriction can be eliminated.
    return _enrich_inventory_procedure_associations(cluster, inventory, procedure_associations,
                                                    enrich_global=False)


def _enrich_inventory_procedure_associations(cluster: KubernetesCluster, inventory: dict,
                                             procedure_associations: dict,
                                             *, enrich_global: bool) -> dict:
    if procedure_associations:
        cluster_associations = inventory.setdefault("services", {}).setdefault("packages", {}) \
            .setdefault("associations", {})
        if not enrich_global:
            cluster_associations = cluster_associations.setdefault(cluster.get_os_family(), {})
        default_merger.merge(cluster_associations, deepcopy(procedure_associations))

    return inventory


def enrich_inventory_include_all(inventory: dict, _: KubernetesCluster) -> dict:
    for _type in ['upgrade', 'remove']:
        packages: dict = inventory['services']['packages'].get(_type)
        if packages is not None:
            packages.setdefault('include', ['*'])

    return inventory


def upgrade_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    # Despite we enrich OS specific section inside enrich_upgrade_inventory(),
    # we still merge global associations section because it has priority during enrichment.
    upgrade_inventory_associations(cluster, inventory, enrich_global=True)
    upgrade_inventory_packages(cluster, inventory)

    return inventory


def migrate_cri_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory

    procedure_associations = cluster.procedure_inventory.get("packages", {}).get("associations", {})
    # Despite we enrich OS specific section inside enrich_migrate_cri_inventory(),
    # we still merge global associations section because it has priority during enrichment.
    return _enrich_inventory_procedure_associations(cluster, inventory, procedure_associations,
                                                    enrich_global=True)


def cache_package_versions(cluster: KubernetesCluster, inventory: dict, by_initial_nodes: bool = False) -> dict:
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
    hosts_to_packages: Dict[str, List[str]] = {}
    for node in group.get_ordered_members_list():
        os_family = node.get_nodes_os()
        node_associations = packages_section['associations'].get(os_family, {})
        for association_name in node_associations.keys():
            host_packages = get_association_hosts_to_packages(
                node, inventory, association_name, ensured_association_only)

            packages: List[str] = next(iter(host_packages.values()), [])
            hosts_to_packages.setdefault(node.get_host(), []).extend(packages)

    custom_install_packages = inventory['services']['packages'].get('install', {}).get('include', [])
    if not ensured_association_only and custom_install_packages:
        for host in group.get_hosts():
            hosts_to_packages.setdefault(host, []).extend(custom_install_packages)

    return hosts_to_packages


def get_association_hosts_to_packages(group: AbstractGroup[RunResult], inventory: dict, association_name: str,
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
    cluster: KubernetesCluster = group.cluster

    packages_section = inventory['services']['packages']
    if not packages_section['mandatory'].get(association_name, True):
        return {}

    hosts_to_packages = {}

    if association_name == 'unzip':
        from kubemarine import thirdparties
        relevant_group: AbstractGroup[RunResult] = thirdparties.get_group_require_unzip(cluster, inventory)
    else:
        groups = cluster.globals['packages']['common_associations'].get(association_name, {}).get('groups', [])
        relevant_group = cluster.make_group_from_roles(groups)

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
                                detected_packages: Dict[str, Dict[str, List]], ensured_association_only: bool) -> None:
    cluster: KubernetesCluster = group.cluster
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
            associated_params['package_name'] = final_packages_list[0]
        else:
            associated_params['package_name'] = final_packages_list


def _cache_custom_packages(cluster: KubernetesCluster, inventory: dict,
                           detected_packages: Dict[str, Dict[str, List]], ensured_association_only: bool) -> None:
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


def remove_unused_os_family_associations(cluster: KubernetesCluster, inventory: dict) -> dict:
    final_nodes = cluster.nodes['all'].get_final_nodes()
    for os_family in get_associations_os_family_keys():
        # Do not remove OS family associations section in finalized inventory if any node has this OS family.
        if final_nodes.get_subgroup_with_os(os_family).is_empty():
            del inventory['services']['packages']['associations'][os_family]

    return inventory


def get_associations_os_family_keys() -> Set[str]:
    return {'debian', 'rhel', 'rhel8', 'rhel9'}


def get_compatibility_version_key(os_family: str) -> str:
    """
    Get os-specific version key to be used in software compatibility map.
    :param os_family: one of supported OS families
    :return: String to use as version key.
    """
    if os_family in get_associations_os_family_keys():
        return f"version_{os_family}"
    else:
        raise ValueError(f"Unsupported {os_family!r} OS family")


class PackageManager(Protocol):
    def ls_repofiles(self, group: NodeGroup) -> RunnersGroupResult: ...

    def backup_repo(self, group: NodeGroup) -> Optional[RunnersGroupResult]: ...

    def add_repo(self, group: NodeGroup, repo_data: Union[List[str], Dict[str, dict], str]) -> RunnersGroupResult: ...

    def get_repo_file_name(self) -> str: ...

    def create_repo_file(self, group: AbstractGroup[RunResult],
                         repo_data: Union[List[str], Dict[str, dict], str],
                         repo_file: str) -> None: ...

    def clean(self, group: NodeGroup) -> RunnersGroupResult: ...

    def get_install_cmd(self, include: Union[str, List[str]], exclude: Union[str, List[str]] = None) -> str: ...

    def install(self, group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
                exclude: Union[str, List[str]] = None,
                callback: Callback = None) -> GROUP_RUN_TYPE: ...

    def remove(self, group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
               exclude: Union[str, List[str]] = None,
               warn: bool = False, hide: bool = True) -> GROUP_RUN_TYPE: ...

    def upgrade(self, group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
                exclude: Union[str, List[str]] = None) -> GROUP_RUN_TYPE: ...

    def no_changes_found(self, action: str, result: RunnersResult) -> bool: ...

    def search(self, group: DeferredGroup, package: str, callback: Callback = None) -> Token: ...


def get_package_manager(group: AbstractGroup[GROUP_RUN_TYPE]) -> PackageManager:
    os_family = group.get_nodes_os()

    if os_family in ['rhel', 'rhel8', 'rhel9']:
        return yum
    elif os_family == 'debian':
        return apt

    raise Exception('Failed to return package manager for unknown or multiple OS')


def ls_repofiles(group: NodeGroup) -> RunnersGroupResult:
    return get_package_manager(group).ls_repofiles(group)


def backup_repo(group: NodeGroup) -> Optional[RunnersGroupResult]:
    return get_package_manager(group).backup_repo(group)


def add_repo(group: NodeGroup, repo_data: Union[List[str], dict, str]) -> RunnersGroupResult:
    return get_package_manager(group).add_repo(group, repo_data)


def get_repo_filename(group: AbstractGroup[RunResult]) -> str:
    return get_package_manager(group).get_repo_file_name()


def create_repo_file(group: AbstractGroup[RunResult], repo_data: Union[List[str], dict, str], repo_file: str) -> None:
    get_package_manager(group).create_repo_file(group, repo_data, repo_file)


def clean(group: NodeGroup) -> RunnersGroupResult:
    return get_package_manager(group).clean(group)


def install(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None,
            callback: Callback = None) -> GROUP_RUN_TYPE:
    return get_package_manager(group).install(group, include, exclude, callback)


def remove(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None, exclude: Union[str, List[str]] = None,
           warn: bool = False, hide: bool = True) -> GROUP_RUN_TYPE:
    return get_package_manager(group).remove(group, include, exclude, warn=warn, hide=hide)


def upgrade(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None) -> GROUP_RUN_TYPE:
    return get_package_manager(group).upgrade(group, include, exclude)


def no_changes_found(group: NodeGroup, action: str, result: RunnersResult) -> bool:
    pkg_mgr = get_package_manager(group)
    return pkg_mgr.no_changes_found(action, result)


def search_package(group: DeferredGroup, package: str, callback: Callback = None) -> Token:
    return get_package_manager(group).search(group, package, callback)


def get_detect_package_version_cmd(os_family: str, package_name: str) -> str:
    if os_family in ["rhel", "rhel8", "rhel9"]:
        cmd = r"rpm -q %s" % package_name
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W %s" % package_name

    return cmd


def _detect_installed_package_version(group: DeferredGroup, package: str, collector: CollectorCallback) -> Token:
    """
    Detect package versions for each host on remote group
    :param group: Group of nodes, where package should be found
    :param package: package name, which version should be detected (eg. 'containerd')
    :return: NodeGroupResults with package version on each host

    Method generates different package query for different OS.

    Note: for Ubuntu/Debian some packages returns multiline results for some queries
    (for example docker-ce* returns docker-ce and docker-ce-cli).
    """

    os_family = group.get_nodes_os()
    package_name = get_package_name(os_family, package)

    cmd = get_detect_package_version_cmd(os_family, package_name)
    return group.sudo(cmd, warn=True, callback=collector)


def _parse_node_detected_package(result: RunnersResult, package: str) -> str:
    node_detected_package = result.stdout.strip() + result.stderr.strip()
    # consider version, which ended with special symbol = or - as not installed
    # (it is possible in some cases to receive "containerd=" version)
    if "not installed" in node_detected_package or "no packages found" in node_detected_package \
            or node_detected_package[-1] == '=' or node_detected_package[-1] == '-':
        node_detected_package = f"not installed {package}"

    return node_detected_package


def detect_installed_packages_version_hosts(
        cluster: KubernetesCluster, hosts_to_packages: Mapping[str, Union[str, List[str]]]
) -> Dict[str, Dict[str, List[str]]]:
    """
    Detect grouped packages versions for specified list of packages for each remote host.

    :param cluster: KubernetesCluster instance
    :param hosts_to_packages: Remote hosts with list of packages to detect versions.
    :return: Dictionary with grouped versions for each queried package, pointing to list of hosts,
        e.g. {"foo" -> {"foo-1": [host1, host2]}, "bar" -> {"bar-1": [host1], "bar-2": [host2]}}
    """
    hosts_to_packages_dedup = {}
    for host, packages_list in hosts_to_packages.items():
        if isinstance(packages_list, str):
            packages_list = [packages_list]
        # deduplicate
        hosts_to_packages_dedup[host] = list(set(packages_list))

    collector = CollectorCallback(cluster)
    with cluster.make_group(hosts_to_packages).new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            for package in hosts_to_packages_dedup[node.get_host()]:
                _detect_installed_package_version(node, package, collector)

    results: Dict[str, Dict[str, List]] = {}

    for host, multiple_results in collector.results.items():
        for i, result in enumerate(multiple_results):
            package = hosts_to_packages_dedup[host][i]
            node_detected_package = _parse_node_detected_package(result, package)
            results.setdefault(package, {}).setdefault(node_detected_package, []).append(host)

    return results


def get_package_version_separator(os_family: str) -> str:
    return '=' if os_family == 'debian' else '-'


def get_package_name(os_family: str, package: str) -> str:
    """
    Return the pure package name, without any part of version
    """

    import re

    package_name = ""

    if package:
        if os_family in ["rhel", "rhel8", "rhel9"]:
            # regexp is needed to split package and its version, the pattern start with '-' then should be number or '*'
            package_name = re.split(r'-[\d,\*]', package)[0]
        else:
            # in ubuntu it is much easier to parse package name
            package_name = package.split("=")[0]

    return package_name
