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
from typing import Dict, List, Union, Iterable, Tuple, Optional, Any, Callable

import yaml

from kubemarine.core import log, utils, static, connections
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.environment import Environment
from kubemarine.core.group import NodeGroup, NodeConfig

_AnyConnectionTypes = Union[str, NodeGroup]


class KubernetesCluster(Environment):

    def __init__(self, inventory: dict, context: dict, procedure_inventory: dict = None,
                 logger: log.EnhancedLogger = None) -> None:
        self.roles: List[str] = []
        self.ips: Dict[str, List[str]] = {
            "all": []
        }
        self.nodes: Dict[str, NodeGroup] = {}

        self.raw_inventory = deepcopy(inventory)
        # Should not be copied. Can be used after successful of failed execution and might store intermediate result.
        self.context = context
        self.procedure_inventory = {} if procedure_inventory is None else deepcopy(procedure_inventory)

        self._connection_pool: ConnectionPool = connections.EMPTY_POOL

        self._logger = logger if logger is not None \
            else log.init_log_from_context_args(self.globals, self.context, self.raw_inventory).logger

        self._inventory: dict = {}

    def enrich(self, custom_enrichment_fns: List[str] = None) -> None:
        # do not make dumps for custom enrichment functions, because result is generally undefined
        make_dumps = custom_enrichment_fns is None
        from kubemarine.core import defaults
        self._inventory = defaults.enrich_inventory(
            self, self.raw_inventory, make_dumps=make_dumps, enrichment_functions=custom_enrichment_fns)

        self._connection_pool = self.create_connection_pool(self.ips['all'])

    @property
    def inventory(self) -> dict:
        return self._inventory

    @property
    def connection_pool(self) -> ConnectionPool:
        return self._connection_pool

    def create_connection_pool(self, hosts: List[str]) -> ConnectionPool:
        return ConnectionPool(self.inventory, hosts)

    @property
    def log(self) -> log.EnhancedLogger:
        return self._logger

    @property
    def globals(self) -> dict:
        return static.GLOBALS

    def make_group(self, ips: Iterable[_AnyConnectionTypes]) -> NodeGroup:
        return NodeGroup(ips, self)

    def get_access_address_from_node(self, node: dict) -> str:
        """
        Returns address which should be used to connect to the node via Fabric.
        The address also can be used as unique identifier of the node.
        """
        address: str
        if node.get('connect_to') is not None:
            address = node['connect_to']
        elif node.get('address') is not None:
            address = node['address']
        else:
            address = node['internal_address']

        return address

    def get_nodes_by_names(self, node_names: List[str]) -> List[dict]:
        result = []
        for node in self.inventory["nodes"]:
            if node['name'] in node_names:
                result.append(node)

        return result

    def get_node_by_name(self, node_name: str) -> Optional[dict]:
        nodes = self.get_nodes_by_names([node_name])
        return next(iter(nodes), None)

    def get_addresses_from_node_names(self, node_names: List[str]) -> List[str]:
        return [self.get_access_address_from_node(node)
                for node in self.get_nodes_by_names(node_names)]

    def get_node(self, host: _AnyConnectionTypes) -> NodeConfig:
        return self.make_group([host]).get_config()

    def make_group_from_nodes(self, node_names: List[str]) -> NodeGroup:
        ips = self.get_addresses_from_node_names(node_names)
        return self.make_group(ips)

    def make_group_from_roles(self, roles: Iterable[str]) -> NodeGroup:
        group = self.make_group([])
        for role in roles:
            if role not in self.nodes:
                self.log.verbose(f'Group {role!r} is requested for usage, but this group does not exist.')
                continue

            group = group.include_group(self.nodes[role])

        return group

    def create_group_from_groups_nodes_names(self, groups_names: List[str], nodes_names: List[str]) -> NodeGroup:
        common_group = self.make_group_from_roles(groups_names)

        if nodes_names:
            common_group = common_group.include_group(self.make_group_from_nodes(nodes_names))

        return common_group

    def schedule_cumulative_point(self, point_method: Callable) -> None:
        from kubemarine.core import flow
        flow.schedule_cumulative_point(self, point_method)

    def is_task_completed(self, task_path: str) -> bool:
        from kubemarine.core import flow
        return flow.is_task_completed(self, task_path)

    def get_facts_enrichment_fns(self) -> List[str]:
        return [
            "kubemarine.core.schema.verify_inventory",
            "kubemarine.core.defaults.merge_defaults",
            "kubemarine.kubernetes.verify_initial_version",
            "kubemarine.kubernetes.add_node_enrichment",
            "kubemarine.kubernetes.remove_node_enrichment",
            "kubemarine.controlplane.controlplane_node_enrichment",
            "kubemarine.core.defaults.append_controlplain",
            "kubemarine.core.defaults.compile_inventory",
            "kubemarine.core.defaults.calculate_node_names",
            "kubemarine.core.defaults.verify_node_names",
            "kubemarine.core.defaults.apply_defaults",
            "kubemarine.core.defaults.calculate_nodegroups"
        ]

    def detect_nodes_context(self) -> dict:
        """The method should fetch only node specific information that is not changed during Kubemarine run"""
        self.log.debug('Start detecting nodes context...')

        from kubemarine import system
        system.whoami(self)
        self.log.verbose('Whoami check finished')

        self._check_online_nodes()
        self._check_accessible_nodes()

        system.detect_active_interface(self)
        self.log.verbose('Interface check finished')
        system.detect_os_family(self)
        self.log.verbose('OS family check finished')

        self.log.debug('Detecting nodes context finished!')
        return deepcopy(self.context['nodes'])

    def _check_online_nodes(self) -> None:
        """
        Check that only subset of nodes for removal can be offline
        """
        all = self.nodes['all']
        for_removal = all.get_nodes_for_removal()
        remained = all.exclude_group(for_removal)
        offline = all.get_online_nodes(False)
        remained_offline = remained.intersection_group(offline)
        if not remained_offline.is_empty():
            raise Exception(f"{remained_offline.get_hosts()} are not reachable. "
                            "Probably they are turned off or something is incorrect with ssh daemon, "
                            "or incorrect ssh port is specified.")

    # todo this check can probably be moved to prepare.check tasks group of each procedure
    def _check_accessible_nodes(self) -> None:
        """
        Check that all online nodes are accessible.
        """
        all = self.nodes['all']
        online = all.get_online_nodes(True)
        accessible = all.get_accessible_nodes()
        not_accessible = all.exclude_group(accessible)
        not_accessible_online = online.intersection_group(not_accessible)
        if not not_accessible_online.is_empty():
            raise Exception(f"{not_accessible_online.get_hosts()} are not accessible through ssh. "
                            f"Check ssh credentials.")

    def get_os_family_for_node(self, host: str) -> str:
        os_family: Optional[str] = self.context['nodes'].get(host, {}).get('os', {}).get('family')
        if os_family is None:
            raise Exception('Node %s do not contain necessary context data' % host)
        return os_family

    def get_os_family_for_nodes(self, hosts: Iterable[str]) -> str:
        """
        Returns the detected operating system family for hosts.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "multiple", "unknown", "unsupported".
        """
        os_families = {self.get_os_family_for_node(host) for host in hosts}
        if len(os_families) > 1:
            return 'multiple'
        elif len(os_families) == 0:
            raise Exception('Cannot get os family for empty nodes list')
        else:
            return list(os_families)[0]

    def get_os_family(self) -> str:
        """
        Returns common OS family name from all final remote hosts.
        The method can be used during enrichment when NodeGroups are not yet calculated.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "multiple", "unknown", "unsupported".
        """
        hosts_detect_os_family = []
        for node in self.inventory['nodes']:
            host = self.get_access_address_from_node(node)
            if 'remove_node' not in node['roles']:
                hosts_detect_os_family.append(host)

        return self.get_os_family_for_nodes(hosts_detect_os_family)

    def get_os_identifiers(self) -> Dict[str, Tuple[str, str]]:
        """
        For each final node of the cluster, returns a tuple of OS (family, version).
        """
        nodes_check_os = self.nodes['all'].get_final_nodes()
        os_ids = {}
        for host in nodes_check_os.get_hosts():
            os_details = self.context['nodes'][host]['os']
            os_ids[host] = (os_details['family'], os_details['version'])

        return os_ids

    def _get_associations(self, os_family: str) -> Dict[str, dict]:
        if os_family in ('unknown', 'unsupported', 'multiple'):
            raise Exception("Failed to get associations for unsupported or multiple OS families")

        associations: dict = self.inventory['services']['packages']['associations'][os_family]
        return associations

    def get_associations(self) -> Dict[str, dict]:
        """
        Returns association for all packages from inventory for the cluster.
        The method can be used only if cluster has nodes with the same and supported OS family.
        """
        return self._get_associations(self.get_os_family())

    def _get_associations_for_os(self, os_family: str, package: str) -> dict:
        associations = self._get_associations(os_family).get(package)
        if associations is None:
            raise Exception(f'Failed to get associations for package "{package}"')

        return associations

    def get_associations_for_node(self, host: str, package: str) -> dict:
        """
        Returns all packages associations for specific node.

        :param host: The address of the node for which required to find the associations
        :param package: The package name to get the associations for
        :return: Dict with packages and their associations
        """
        node_os_family = self.get_os_family_for_node(host)
        return self._get_associations_for_os(node_os_family, package)

    def _get_package_associations_for_os(self, os_family: str, package: str, association_key: str) -> Any:
        associations = self._get_associations_for_os(os_family, package)
        association_value = associations.get(association_key)
        if association_value is None:
            raise Exception(f'Failed to get association "{association_key}" for package "{package}"')
        if not isinstance(association_value, str) and not isinstance(association_value, list):
            raise Exception(f'Unsupported association "{association_key}" value type for package "{package}", '
                            f'got: {str(association_value)}')

        return association_value

    def get_package_association(self, package: str, association_key: str) -> Any:
        """
        Returns the specified association for the specified package from inventory for the cluster.
        The method can be used only if cluster has nodes with the same and supported OS family.

        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family()
        return self._get_package_associations_for_os(os_family, package, association_key)

    def get_package_association_for_node(self, host: str, package: str, association_key: str) -> Any:
        """
        Returns the specified association for the specified package from inventory for specific node.

        :param host: The address of the node for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family_for_node(host)
        return self._get_package_associations_for_os(os_family, package, association_key)

    def make_finalized_inventory(self) -> dict:
        from kubemarine.core import defaults
        from kubemarine.procedures import add_node, remove_node
        from kubemarine import admission, controlplane, cri, packages

        cluster_finalized_functions: List[Callable[[KubernetesCluster, dict], dict]] = [
            packages.cache_package_versions,
            packages.remove_unused_os_family_associations,
            cri.remove_invalid_cri_config,
            add_node.add_node_finalize_inventory,
            remove_node.remove_node_finalize_inventory,
            admission.update_finalized_inventory,
            defaults.escape_jinja_characters_for_inventory,
            controlplane.controlplane_finalize_inventory,
        ]

        # copying is currently not necessary, but it is possible in general.
        prepared_inventory = self.inventory
        for finalize_fn in cluster_finalized_functions:
            prepared_inventory = finalize_fn(self, prepared_inventory)

        return defaults.prepare_for_dump(prepared_inventory, copy=False)

    def dump_finalized_inventory(self) -> None:
        inventory_for_dump = self.make_finalized_inventory()
        data = yaml.dump(inventory_for_dump)
        finalized_filename = "cluster_finalized.yaml"
        utils.dump_file(self, data, finalized_filename)
        utils.dump_file(self, data, finalized_filename, dump_location=False)

    def preserve_inventory(self) -> None:
        self.log.debug("Start preserving of the information about the procedure.")
        cluster_storage = utils.ClusterStorage(self)
        cluster_storage.make_dir()
        if self.context.get('initial_procedure') == 'add_node':
            cluster_storage.upload_info_new_control_planes()
        cluster_storage.collect_procedure_info()
        cluster_storage.compress_and_upload_archive()
        cluster_storage.rotation_file()
