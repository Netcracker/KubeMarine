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
from typing import Dict, List, Union


import fabric
import yaml


from kubemarine.core import log
from kubemarine.core.connections import ConnectionPool, Connections
from kubemarine.core.environment import Environment
from kubemarine.core.group import NodeGroup

jinja_query_regex = re.compile("{{ .* }}", re.M)

_AnyConnectionTypes = Union[str, NodeGroup, fabric.connection.Connection]


class KubernetesCluster(Environment):

    def __init__(self, inventory, context, procedure_inventory=None, gather_facts=False):

        self.supported_roles = [
            "balancer",
            "master",
            "worker"
        ]

        self.roles = []
        self.ips = {
            "all": []
        }
        self.nodes: Dict[str, NodeGroup] = {}

        self.context = context
        self.context['runtime_vars'] = {}

        with open(utils.get_resource_absolute_path('resources/configurations/globals.yaml',
                                                   script_relative=True), 'r') as stream:
            self._globals = yaml.safe_load(stream)

        with open(utils.get_resource_absolute_path('resources/configurations/defaults.yaml',
                                                   script_relative=True), 'r') as stream:
            self._defaults = yaml.safe_load(stream)

        if isinstance(inventory, dict):
            self.raw_inventory = deepcopy(inventory)
        else:
            with open(inventory, 'r') as stream:
                self.raw_inventory = yaml.safe_load(stream)

        self._log = log.init_log_from_context_args(self)

        self.procedure_inventory = {}
        if procedure_inventory is not None:
            if isinstance(procedure_inventory, dict):
                self.procedure_inventory = deepcopy(procedure_inventory)
            else:
                with open(procedure_inventory, 'r') as stream:
                    self.procedure_inventory = yaml.safe_load(stream)

        self._inventory = {}
        self._connection_pool = ConnectionPool(self)

        if gather_facts:
            self.gather_facts('before')

        self._inventory = defaults.enrich_inventory(self, self.raw_inventory)

    @property
    def inventory(self) -> dict:
        return self._inventory

    @property
    def globals(self) -> dict:
        return self._globals

    @property
    def defaults(self) -> dict:
        return self._defaults

    @property
    def log(self) -> log.EnhancedLogger:
        return self._log.logger

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

    def get_addresses_from_node_names(self, node_names: List[str]) -> dict:
        result = {}
        for node in self.inventory["nodes"]:
            for requested_node_name in node_names:
                if requested_node_name == node['name']:
                    result[node['name']] = {
                        'address': node.get('address'),
                        'internal_address': node.get('internal_address'),
                        'connect_to': node.get('connect_to')
                    }
        return result

    def make_group_from_nodes(self, node_names: List[str]) -> NodeGroup:
        addresses = self.get_addresses_from_node_names(node_names)
        ips = []
        for item in list(addresses.values()):
            ips.append(item['connect_to'])
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
        return flow.schedule_cumulative_point(self, point_method)

    def is_task_completed(self, task_path) -> bool:
        return flow.is_task_completed(self, task_path)

    def get_final_inventory(self):
        return utils.get_final_inventory(self)

    def get_facts_enrichment_fns(self):
        return [
            "kubemarine.kubernetes.add_node_enrichment",
            "kubemarine.kubernetes.remove_node_enrichment",
            "kubemarine.core.defaults.append_controlplain",
            "kubemarine.core.defaults.compile_inventory",
            "kubemarine.core.defaults.calculate_node_names",
            "kubemarine.core.defaults.apply_defaults",
            "kubemarine.core.defaults.calculate_nodegroups"
        ]

    def gather_facts(self, step) -> None:
        self.log.debug('Gathering facts started...')

        if step == 'before':
            t_cluster = deepcopy(self)
            defaults.enrich_inventory(t_cluster, t_cluster.raw_inventory, make_dumps=False, custom_fns=self.get_facts_enrichment_fns())

            for node in t_cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
                t_cluster.context['nodes'][node['connect_to']] = {
                    "name": node['name'],
                    "roles": node['roles'],
                    "online": False
                }

            system.whoami(t_cluster.nodes['all'])
            self.log.verbose('Whoami check finished')
            system.detect_active_interface(t_cluster.nodes['all'].get_online_nodes())
            self.log.verbose('Interface check finished')
            system.detect_os_family(t_cluster, suppress_exceptions=True)
            self.log.verbose('OS family check finished')
            self.context = t_cluster.context
        elif step == 'after':
            self.remove_invalid_cri_config(self.inventory)
            # Method "kubemarine.system.is_multiple_os_detected" is not used because it detects OS family for new nodes
            # only, while package versions caching performs on all nodes.
            if self.nodes['all'].get_nodes_os(suppress_exceptions=True, force_all_nodes=True) != 'multiple':
                self.cache_package_versions()
                self.log.verbose('Package versions detection finished')
            else:
                self.log.verbose('Package versions detection cancelled - cluster in multiple OS state')

        self.log.debug('Gathering facts finished!')

    def get_associations_for_os(self, os_family):
        package_associations = self.inventory['services']['packages']['associations']
        active_os_family = system.get_os_family(self)
        if active_os_family != os_family:
            package_associations = package_associations[os_family]

        return package_associations

    def get_os_family_for_node(self, host: str) -> str:
        node_context = self.context['nodes'].get(host)
        if not node_context or not node_context.get('os', {}).get('family'):
            raise Exception('Node %s do not contain necessary context data' % host)
        return node_context['os']['family']

    def get_associations_for_node(self, host: str) -> dict:
        """
        Returns all packages associations for specific node
        :param host: The address of the node for which required to find the associations
        :return: Dict with packages and their associations
        """
        node_os_family = self.get_os_family_for_node(host)
        return self.get_associations_for_os(node_os_family)

    def get_package_association_for_node(self, host: str, package: str, association_key: str) -> str or list:
        """
        Returns the specified association for the specified package from inventory for specific node
        :param host: The address of the node for which required to find the association
        :param package: The package name to get the association for
        :param association_key: Association key to get
        :return: Association string or list value
        """
        associations = self.get_associations_for_node(host)
        association_value = associations.get(package, {}).get(association_key)
        if association_value is None:
            raise Exception(f'Failed to get association "{association_key}" for package "{package}"')
        if not isinstance(association_value, str) and not isinstance(association_value, list):
            raise Exception(f'Unsupported association "{association_key}" value type for package "{package}", '
                            f'got: {str(association_value)}')
        return association_value

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

    def cache_package_versions(self):
        detected_packages = packages.detect_installed_packages_version_groups(self.nodes['all'].get_unchanged_nodes().get_online_nodes())
        for os_family in ['debian', 'rhel', 'rhel8']:
            if self.inventory['services']['packages']['associations'].get(os_family):
                del self.inventory['services']['packages']['associations'][os_family]
        for association_name, associated_params in self.inventory['services']['packages']['associations'].items():
            associated_packages = associated_params.get('package_name', [])
            packages_list = []
            final_packages_list = []
            if isinstance(associated_packages, str):
                packages_list.append(associated_packages)
            elif isinstance(associated_packages, list):
                packages_list = packages_list + associated_packages
            else:
                raise Exception('Unsupported associated packages object type')

            for package in packages_list:
                detected_package_versions = list(detected_packages[package].keys())
                for version in detected_package_versions:
                    # add package version to list only if it was found as installed
                    # skip version, which ended with special symbol = or -
                    # (it is possible in some cases to receive "containerd=" version)
                    if "not installed" not in version and version[-1] != '=' and version[-1] != '-':
                        final_packages_list.append(version)

                # if there no versions detected, then set package version to default
                if not final_packages_list:
                    final_packages_list = [package]

            # if non-multiple value, then convert to simple string
            # packages can contain multiple package values, like docker package
            # (it has docker-ce, docker-cli and containerd.io packages for installation)
            if len(final_packages_list) == 1:
                final_packages_list = final_packages_list[0]
            else:
                final_packages_list = list(set(final_packages_list))

            associated_params['package_name'] = final_packages_list
        # packages from direct installation section
        if self.inventory['services']['packages']['install']:
            final_packages_list = []
            for package in self.inventory['services']['packages']['install']['include']:
                package_versions_list = []
                detected_package_versions = list(detected_packages[package].keys())
                for version in detected_package_versions:
                    # skip version, which ended with special symbol = or -
                    # (it is possible in some cases)
                    if "not installed" not in version and version[-1] != '=' and version[-1] != '-':
                        # add package version to list only if it was found as installed
                        package_versions_list.append(version)
                # if there no versions detected, then set package version to default
                if not package_versions_list:
                    package_versions_list = [package]
                final_packages_list = final_packages_list + package_versions_list
            self.inventory['services']['packages']['install']['include'] = list(set(final_packages_list))
        return detected_packages

    def finish(self):
        self.gather_facts('after')
        # TODO: rewrite the following lines as deenrichment functions like common enrichment mechanism
        from kubemarine.procedures import remove_node
        prepared_inventory = remove_node.remove_node_finalize_inventory(self, self.inventory)
        prepared_inventory = defaults.prepare_for_dump(prepared_inventory, copy=False)
        prepared_inventory = self.escape_jinja_characters_for_inventory(prepared_inventory)
        output = yaml.dump(prepared_inventory)
        utils.dump_file(self, output, "cluster_finalized.yaml")
        cluster_storage = utils.ClusterStorage.get_instance(self)
        cluster_storage.collect_procedure_info(self)
        cluster_storage.comprese_and_upload_archive(self)
        cluster_storage.rotation_file(self)


    def escape_jinja_characters_for_inventory(self, obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = self.escape_jinja_characters_for_inventory(value)
        elif isinstance(obj, list):
            for key, value in enumerate(obj):
                obj[key] = self.escape_jinja_characters_for_inventory(value)
        elif isinstance(obj, str):
            obj = self.escape_jinja_character(obj)
        return obj

    def escape_jinja_character(self, value):
        if '{{' in value and '}}' in value and re.search(jinja_query_regex, value):
            matches = re.findall(jinja_query_regex, value)
            for match in matches:
                # TODO: rewrite to correct way of match replacement: now it can cause "{raw}{raw}xxx.." circular bug
                value = value.replace(match, '{% raw %}'+match+'{% endraw %}')
        return value

    def remove_invalid_cri_config(self, inventory):
        if inventory['services']['cri']['containerRuntime'] == 'docker':
            if inventory['services']['cri'].get('containerdConfig'):
                del inventory['services']['cri']['containerdConfig']
        elif inventory['services']['cri'].get('dockerConfig'):
            del inventory['services']['cri']['dockerConfig']

from kubemarine import system, packages
from kubemarine.core import defaults, flow, utils
