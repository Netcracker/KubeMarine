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
import re
from typing import List, Dict, Tuple, Optional, Union, Mapping, Set, Protocol
from io import StringIO

from kubemarine import yum, apt, jinja
from kubemarine.core import errors, static, utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
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


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    enrich_inventory_associations(cluster)
    enrich_inventory_packages(cluster)


def enrich_inventory_associations(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
    associations: dict = inventory['services']['packages']['associations']
    inventory['services']['packages']['associations'] = enriched_associations = {}

    # Move associations for OS families and merge with globals
    for association_name in get_associations_os_family_keys():
        redefined_associations = associations.pop(association_name)
        if cluster.nodes['all'].get_subgroup_with_os(association_name).is_empty():
            continue

        os_associations = utils.deepcopy_yaml(static.GLOBALS['packages']['common_associations'])
        if association_name == 'debian':
            del os_associations['semanage']
        for association_params in os_associations.values():
            del association_params['groups']

        for package in static.GLOBALS['packages'][association_name]:
            os_associations[package]['package_name']\
                = get_default_package_names(association_name, package, kubernetes_version)

        default_merger.merge(os_associations, redefined_associations)
        enriched_associations[association_name] = os_associations

    # Check remained associations section if they are customized at global level.
    if associations:
        os_family = cluster.get_os_family()
        if os_family == 'multiple':
            raise Exception(ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS)
        elif os_family not in ('unknown', 'unsupported', '<undefined>'):
            # move remained associations properties to the specific OS family section and merge with priority
            default_merger.merge(enriched_associations[os_family], associations)

    if 'semanage' in enriched_associations.get('debian', {}):
        raise Exception(ERROR_SEMANAGE_NOT_MANAGED_DEBIAN)


def enrich_inventory_packages(cluster: KubernetesCluster) -> None:
    for _type in ['install', 'upgrade', 'remove']:
        packages_list = cluster.inventory['services']['packages'].get(_type)
        if isinstance(packages_list, list):
            cluster.inventory['services']['packages'][_type] = {
                'include': packages_list
            }

    for _type in ['upgrade', 'remove']:
        packages: dict = cluster.inventory['services']['packages'].get(_type)
        if packages is not None:
            packages.setdefault('include', ['*'])


def _get_associations_procedure_plan(cluster: KubernetesCluster) -> List[Tuple[str, dict]]:
    context = cluster.context
    procedure = context["initial_procedure"]
    procedure_inventory = cluster.procedure_inventory
    upgrade_plan = []
    if procedure == "upgrade":
        kubernetes_version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        for i, v in enumerate(procedure_inventory['upgrade_plan'][context['upgrade_step']:]):
            # Take the target (probably) compiled version and the remained not yet compiled
            version = kubernetes_version if i == 0 else v
            procedure_associations = procedure_inventory.get(v, {}).get("packages", {}).get("associations", {})
            procedure_associations = utils.subdict_yaml(procedure_associations,
                                                        _get_system_packages_support_upgrade(cluster))

            upgrade_plan.append((version, procedure_associations))

    elif procedure == "migrate_kubemarine" and "upgrading_package" in context:
        procedure_associations = procedure_inventory.get('upgrade', {}).get("packages", {}).get("associations", {})
        procedure_associations = utils.subdict_yaml(procedure_associations,
                                                    _get_system_packages_support_upgrade(cluster))
        upgrade_plan = [("", procedure_associations)]

    return upgrade_plan


def _get_redefined_package_name(cluster: KubernetesCluster, associations: dict, package: str) \
        -> Optional[List[str]]:
    # Global section has priority
    package_name: Union[str, List[str], None] = associations.get(package, {}).get('package_name')
    if not package_name:
        package_name = associations.get(cluster.get_os_family(), {}).get(package, {}).get('package_name')

    return [package_name] if isinstance(package_name, str) else package_name


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade', 'migrate_kubemarine'])
def enrich_procedure_inventory(cluster: KubernetesCluster) -> None:
    procedure_plan = _get_associations_procedure_plan(cluster)
    procedure_associations = {} if not procedure_plan else procedure_plan[0][1]

    if procedure_associations:
        # Merge global associations section because it has priority during enrichment.
        cluster_associations = cluster.inventory.setdefault("services", {}).setdefault("packages", {}) \
            .setdefault("associations", {})
        default_merger.merge(cluster_associations, utils.deepcopy_yaml(procedure_associations))

    if cluster.context['initial_procedure'] == 'upgrade':
        upgrade_inventory_packages(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade', 'migrate_kubemarine',])
def verify_procedure_inventory(cluster: KubernetesCluster) -> None:
    context = cluster.context
    procedure = context["initial_procedure"]

    os_family = cluster.get_os_family()
    if os_family not in get_associations_os_family_keys():
        raise errors.KME("KME0012", procedure=procedure)

    upgrade_plan = _get_associations_procedure_plan(cluster)
    if not upgrade_plan:
        return

    if procedure == "upgrade":
        previous_version = cluster.previous_inventory['services']['kubeadm']['kubernetesVersion']
    else:  # migrate_kubemarine procedure
        previous_version = ""

    packages_verify = _get_system_packages_support_upgrade(cluster)
    _verify_upgrade_plan(cluster, previous_version, packages_verify, upgrade_plan)


def upgrade_inventory_packages(cluster: KubernetesCluster) -> None:
    procedure_inventory = cluster.procedure_inventory
    upgrade_version = cluster.procedure_inventory['upgrade_plan'][cluster.context['upgrade_step']]
    for _type in ['install', 'upgrade', 'remove']:
        packages_section = procedure_inventory.get(upgrade_version, {}).get("packages", {})
        upgrade_packages = packages_section.get(_type)
        if upgrade_packages is None:
            continue
        if isinstance(upgrade_packages, list):
            upgrade_packages = {'include': upgrade_packages}

        packages_section = cluster.inventory.setdefault("services", {}).setdefault("packages", {})
        inventory_packages = packages_section.setdefault(_type, {})
        if isinstance(inventory_packages, list):
            packages_section[_type] = inventory_packages = {
                'include': inventory_packages
            }

        default_merger.merge(inventory_packages, upgrade_packages)


def _verify_upgrade_plan(cluster: KubernetesCluster, previous_version: str,
                         packages_verify: List[str], upgrade_plan: List[Tuple[str, dict]]) -> None:
    raw_associations = utils.deepcopy_yaml(cluster.previous_raw_inventory.get('services', {}).get('packages', {})
                                           .get('associations', {}))

    # validate all packages sections in procedure inventory
    for version, upgrade_associations in upgrade_plan:
        if version != '' and jinja.is_template(version):
            break

        for package in packages_verify:
            upgrade_package_name = upgrade_associations.get(package, {}).get('package_name')
            if _get_redefined_package_name(cluster, raw_associations, package) and not upgrade_package_name:
                raise errors.KME("KME0010", package=package,
                                 previous_version_spec=f' for version {previous_version}' if previous_version else "",
                                 next_version_spec=f' for version {version}' if version else "")

        default_merger.merge(raw_associations, utils.deepcopy_yaml(upgrade_associations))
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


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade', 'migrate_kubemarine'])
def calculate_upgrade_required(cluster: KubernetesCluster) -> None:
    os_family = cluster.get_os_family()

    context = cluster.context
    system_packages = _get_system_packages_support_upgrade(cluster)
    upgrade_required = context.setdefault("upgrade", {}).setdefault('required', {}).setdefault('packages', [])
    for package in system_packages:
        if (cluster.previous_inventory["services"]["packages"]["associations"][os_family][package]['package_name']
                != cluster.inventory["services"]["packages"]["associations"][os_family][package]['package_name']):
            upgrade_required.append(package)
            continue

        raw_associations = (cluster.previous_raw_inventory.get('services', {}).get('packages', {})
                            .get('associations', {}))
        raw_package_name = _get_redefined_package_name(cluster, raw_associations, package)
        if (context['initial_procedure'] == 'migrate_kubemarine'
                and (not raw_package_name or any(jinja.is_template(pkg) for pkg in raw_package_name))):
            # If package name is redefined with template,
            # upgrade may be required as we have lost previous compilation result.
            upgrade_required.append(package)


def _get_system_packages_support_upgrade(cluster: KubernetesCluster) -> List[str]:
    context = cluster.context
    procedure = context["initial_procedure"]
    if procedure == 'upgrade':
        return ['containerd']
    elif procedure == "migrate_kubemarine" and "upgrading_package" in context:
        return [context['upgrading_package']]

    return []


def cache_package_versions(cluster: KubernetesCluster, inventory: dict, by_initial_nodes: bool = False) -> dict:
    if cluster.get_os_family() == '<undefined>':
        # All nodes are inaccessible. This is possible only in check_iaas.
        return inventory

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

    group = (cluster.previous_nodes if by_initial_nodes else cluster.nodes)['all'] \
        .exclude_group(cluster.nodes['all'].get_online_nodes(False))

    if group.nodes_amount() != group.get_sudo_nodes().nodes_amount():
        # For add_node/install procedures we check that all nodes are sudoers in prepare.check.sudoer task.
        # For check_iaas procedure the nodes might still be not sudoers.
        # Skip caching if any not-sudoer node found.
        cluster.log.debug(f"Some nodes are not sudoers, packages will not be cached.")
        return inventory

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

    relevant_group = relevant_group.intersection_group(group)

    for node in relevant_group.get_ordered_members_list():
        os_family = node.get_nodes_os()
        packages = get_association_packages(cluster, os_family, association_name)

        if ensured_association_only and not cache_versions_enabled(cluster, os_family, association_name):
            packages = []

        if packages:
            hosts_to_packages[node.get_host()] = packages

    return hosts_to_packages


def get_association_packages(cluster: KubernetesCluster, os_family: str, association_name: str) -> List[str]:
    packages_section = cluster.inventory['services']['packages']
    package_associations = packages_section['associations'].get(os_family, {}).get(association_name, {})
    packages: Union[str, List[str]] = package_associations.get('package_name', [])

    if isinstance(packages, str):
        packages = [packages]

    return packages


def cache_versions_enabled(cluster: KubernetesCluster, os_family: str, association_name: str) -> bool:
    packages_section = cluster.inventory['services']['packages']
    global_cache_versions = packages_section['cache_versions']
    specific_cache_versions: bool = packages_section['associations'] \
        .get(os_family, {}).get(association_name, {}).get('cache_versions', True)

    return global_cache_versions and specific_cache_versions


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
        # packages can contain multiple package values
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


def disable_unattended_upgrade(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    if group.get_nodes_os() != 'debian':
        cluster.log.debug("Skipped - unattended upgrades are supported only on Ubuntu/Debian os family")
        return

    packages_per_node = get_all_managed_packages_for_group(group=group, inventory=cluster.inventory,
                                                           ensured_association_only=True)

    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            packages = [get_package_name(node.get_nodes_os(), package) for package in packages_per_node[node.get_host()]]
            unattended_upgrade_config = 'Unattended-Upgrade::Package-Blacklist { %s };\n' % " ".join(
                ['"%s";' % package for package in packages])
            node.put(StringIO(unattended_upgrade_config), '/etc/apt/apt.conf.d/51unattended-upgrades-kubemarine',
                     sudo=True, backup=True)


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
                pty: bool = False, callback: Callback = None) -> GROUP_RUN_TYPE: ...

    def remove(self, group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
               exclude: Union[str, List[str]] = None,
               warn: bool = False, hide: bool = True, pty: bool = False) -> GROUP_RUN_TYPE: ...

    def upgrade(self, group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
                exclude: Union[str, List[str]] = None,
                pty: bool = False) -> GROUP_RUN_TYPE: ...

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
            pty: bool = False, callback: Callback = None) -> GROUP_RUN_TYPE:
    return get_package_manager(group).install(group, include, exclude,
                                              pty=pty, callback=callback)


def remove(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None, exclude: Union[str, List[str]] = None,
           warn: bool = False, hide: bool = True, pty: bool = False) -> GROUP_RUN_TYPE:
    return get_package_manager(group).remove(group, include, exclude, warn=warn, hide=hide, pty=pty)


def upgrade(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None,
            pty: bool = False) -> GROUP_RUN_TYPE:
    return get_package_manager(group).upgrade(group, include, exclude, pty=pty)


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

    package_name = ""

    if package:
        if os_family in ["rhel", "rhel8", "rhel9"]:
            # regexp is needed to split package and its version, the pattern start with '-' then should be number or '*'
            package_name = re.split(r'-[\d,\*]', package)[0]
        else:
            # in ubuntu it is much easier to parse package name
            package_name = package.split("=")[0]

    return package_name
