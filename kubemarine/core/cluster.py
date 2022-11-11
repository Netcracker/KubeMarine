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
from copy import deepcopy
from typing import Dict, List, Union, Iterable, Tuple

import fabric
import yaml

from kubemarine.core import log, utils
from kubemarine.core.connections import ConnectionPool, Connections
from kubemarine.core.environment import Environment
from kubemarine.core.group import NodeGroup

jinja_query_regex = re.compile("{{ .* }}", re.M)

_AnyConnectionTypes = Union[str, NodeGroup, fabric.connection.Connection]


class KubernetesCluster(Environment):

    def __init__(self, inventory: dict, context: dict, procedure_inventory: dict = None,
                 logger: log.EnhancedLogger = None):

        self.supported_roles = [
            "balancer",
            "master",
            "worker",
            "control-plane"
        ]

        self.roles = []
        self.ips = {
            "all": []
        }
        self.nodes: Dict[str, NodeGroup] = {}

        self.raw_inventory = deepcopy(inventory)
        self.context = deepcopy(context)
        self.procedure_inventory = {} if procedure_inventory is None else deepcopy(procedure_inventory)

        self._logger = logger if logger is not None \
            else log.init_log_from_context_args(self.globals, self.context, self.raw_inventory).logger

        self._inventory = {}
        # connection pool should be created every time, because it is relied on partially enriched inventory
        self._connection_pool = ConnectionPool(self)

    def enrich(self, custom_enrichment_fns: List[str] = None):
        # do not make dumps for custom enrichment functions, because result is generally undefined
        make_dumps = custom_enrichment_fns is None
        from kubemarine.core import defaults
        self._inventory = defaults.enrich_inventory(
            self, self.raw_inventory, make_dumps=make_dumps, custom_fns=custom_enrichment_fns)

    @property
    def inventory(self) -> dict:
        return self._inventory

    @property
    def log(self) -> log.EnhancedLogger:
        return self._logger

    def make_group(self, ips: List[_AnyConnectionTypes]) -> NodeGroup:
        connections: Connections = {}
        for ip in ips:
            if isinstance(ip, fabric.connection.Connection):
                ip = ip.host
                connections[ip] = self._connection_pool.get_connection(ip)
            elif isinstance(ip, NodeGroup):
                for host, connection in ip.nodes.items():
                    ip = connection.host
                    connections[ip] = self._connection_pool.get_connection(ip)
            elif isinstance(ip, str):
                connections[ip] = self._connection_pool.get_connection(ip)
            else:
                raise Exception('Unsupported connection object type')
        return NodeGroup(connections, self)

    def get_access_address_from_node(self, node: dict):
        address = node.get('connect_to')
        if address is None:
            address = node.get('address')
        if address is None:
            address = node.get('internal_address')

        return address

    def get_addresses_from_node_names(self, node_names: List[str]) -> List[str]:
        result = []
        for node in self.inventory["nodes"]:
            for requested_node_name in node_names:
                if requested_node_name == node['name']:
                    result.append(self.get_access_address_from_node(node))
        return result

    def get_node(self, host: Union[str, fabric.connection.Connection]) -> dict:
        return self.make_group([host]).get_first_member(provide_node_configs=True)

    def make_group_from_nodes(self, node_names: List[str]) -> NodeGroup:
        ips = self.get_addresses_from_node_names(node_names)
        return self.make_group(ips)

    def create_group_from_groups_nodes_names(self, groups_names: List[str], nodes_names: List[str]) -> NodeGroup:
        common_group = None

        if nodes_names:
            common_group = self.make_group_from_nodes(nodes_names)

        if groups_names:
            for group in groups_names:

                if group not in self.roles:
                    self.log.verbose('Group \'%s\' is requested for usage, but this group is not exists.' % group)
                    continue

                if common_group is None:
                    common_group = self.nodes[group]
                else:
                    common_group = common_group.include_group(self.nodes[group])

        return common_group

    def schedule_cumulative_point(self, point_method):
        from kubemarine.core import flow
        return flow.schedule_cumulative_point(self, point_method)

    def is_task_completed(self, task_path) -> bool:
        from kubemarine.core import flow
        return flow.is_task_completed(self, task_path)

    def get_final_inventory(self):
        return utils.get_final_inventory(self)

    def get_facts_enrichment_fns(self):
        return [
            "kubemarine.kubernetes.add_node_enrichment",
            "kubemarine.kubernetes.remove_node_enrichment",
            "kubemarine.controlplane.controlplane_node_enrichment",
            "kubemarine.core.defaults.append_controlplain",
            "kubemarine.core.defaults.compile_inventory",
            "kubemarine.core.defaults.calculate_node_names",
            "kubemarine.core.defaults.apply_defaults",
            "kubemarine.core.defaults.calculate_nodegroups"
        ]

    def detect_nodes_context(self) -> dict:
        """The method should fetch only node specific information that is not changed during Kubemarine run"""
        self.log.debug('Start detecting nodes context...')

        for node in self.nodes['all'].get_ordered_members_list(provide_node_configs=True):
            self.context['nodes'][node['connect_to']] = {
                "name": node['name'],
                "roles": node['roles']
            }

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

    def _check_online_nodes(self):
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
    def _check_accessible_nodes(self):
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
        node_context = self.context['nodes'].get(host)
        if not node_context or not node_context.get('os', {}).get('family'):
            raise Exception('Node %s do not contain necessary context data' % host)
        return node_context['os']['family']

    def get_os_family_for_nodes(self, hosts: Iterable[str]) -> str:
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
        nodes_check_os = self.nodes['all'].get_final_nodes()
        os_ids = {}
        for host in nodes_check_os.get_hosts():
            os_details = self.context['nodes'][host]['os']
            os_ids[host] = (os_details['family'], os_details['version'])

        return os_ids

    def _get_associations_for_os(self, os_family: str, package: str) -> dict:
        if os_family in ('unknown', 'unsupported', 'multiple'):
            raise Exception("Failed to get associations for unsupported or multiple OS families")

        associations = self.inventory['services']['packages']['associations'][os_family].get(package)
        if associations is None:
            raise Exception(f'Failed to get associations for package "{package}"')

        return associations

    def get_associations_for_node(self, host: str, package: str) -> dict:
        """
        Returns all packages associations for specific node
        :param host: The address of the node for which required to find the associations
        :param package: The package name to get the associations for
        :return: Dict with packages and their associations
        """
        node_os_family = self.get_os_family_for_node(host)
        return self._get_associations_for_os(node_os_family, package)

    def _get_package_associations_for_os(self, os_family: str, package: str, association_key: str) -> str or list:
        associations = self._get_associations_for_os(os_family, package)
        association_value = associations.get(association_key)
        if association_value is None:
            raise Exception(f'Failed to get association "{association_key}" for package "{package}"')
        if not isinstance(association_value, str) and not isinstance(association_value, list):
            raise Exception(f'Unsupported association "{association_key}" value type for package "{package}", '
                            f'got: {str(association_value)}')

    def get_package_association(self, package: str, association_key: str) -> str or list:
        """
        Returns the specified association for the specified package from inventory for the cluster.
        The method can be used only if cluster has nodes with the same and supported OS family.
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family()
        return self._get_package_associations_for_os(os_family, package, association_key)

    def get_package_association_for_node(self, host: str, package: str, association_key: str) -> str or list:
        """
        Returns the specified association for the specified package from inventory for specific node
        :param host: The address of the node for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        os_family = self.get_os_family_for_node(host)
        return self._get_package_associations_for_os(os_family, package, association_key)

    def get_package_association_for_group(self, group: NodeGroup, package: str, association_key: str) -> dict:
        """
        Returns the specified association dict for the specified package from inventory for entire NodeGroup
        :param group: NodeGroup for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association values for every host in group, e.g. { host -> value }
        """
        results = {}
        for node in group.get_ordered_members_list(provide_node_configs=True):
            association_value = self.get_package_association_for_node(node['connect_to'], package, association_key)
            results[node['connect_to']] = association_value
        return results

    def get_package_association_str_for_group(self, group: NodeGroup,
                                              package: str, association_key: str) -> str or list:
        """
        Returns the specified association string or list for the specified package from inventory for entire NodeGroup.
        If association value is different between some nodes, an exception will be thrown.
        :param group: NodeGroup for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        results = self.get_package_association_for_group(group, package, association_key)
        results_values = list(set(results.values()))
        if len(results_values) == 1:
            return results_values[0]
        raise Exception(f'Too many values returned for package associations str "{association_key}" for package "{package}"')

    def dump_finalized_inventory(self):
        from kubemarine.core import defaults
        from kubemarine.procedures import remove_node
        from kubemarine import controlplane, cri, packages

        cluster_finalized_functions = {
            packages.cache_package_versions,
            packages.remove_unused_os_family_associations,
            cri.remove_invalid_cri_config,
            remove_node.remove_node_finalize_inventory,
            defaults.escape_jinja_characters_for_inventory,
            controlplane.controlplane_finalize_inventory,
        }

        # copying is currently not necessary, but it is possible in general.
        prepared_inventory = self.inventory
        for finalize_fn in cluster_finalized_functions:
            prepared_inventory = finalize_fn(self, prepared_inventory)

        inventory_for_dump = defaults.prepare_for_dump(prepared_inventory, copy=False)
        data = yaml.dump(inventory_for_dump)
        finalized_filename = "cluster_finalized.yaml"
        utils.dump_file(self, data, finalized_filename)
        with open(finalized_filename, 'w') as f:
            f.write(data)

    def preserve_inventory(self):
        self.log.debug("Start preserving of the information about the procedure.")
        cluster_storage = utils.ClusterStorage(self)
        cluster_storage.make_dir()
        if self.context.get('initial_procedure') == 'add_node':
            cluster_storage.upload_info_new_control_planes()
        cluster_storage.collect_procedure_info()
        cluster_storage.compress_and_upload_archive()
        cluster_storage.rotation_file()
