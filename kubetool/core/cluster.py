#!/usr/bin/env python3
import re
from copy import deepcopy
from typing import Dict, List

import yaml

from kubetool.core import log
from kubetool.core.connections import ConnectionPool, Connections
from kubetool.core.environment import Environment
from kubetool.core.group import NodeGroup

jinja_query_regex = re.compile("{{ .* }}", re.M)


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

    def make_group(self, ips: List[str] or List[NodeGroup]) -> NodeGroup:
        connections: Connections = {}
        for ip in ips:
            if isinstance(ip, NodeGroup):
                ip = list(ip.nodes.keys())[0]
            connections[ip] = self._connection_pool.get_connection(ip)
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
            "kubetool.kubernetes.add_node_enrichment",
            "kubetool.kubernetes.remove_node_enrichment",
            "kubetool.core.defaults.append_controlplain",
            "kubetool.core.defaults.compile_inventory",
            "kubetool.core.defaults.calculate_node_names",
            "kubetool.core.defaults.apply_defaults",
            "kubetool.core.defaults.calculate_nodegroups"
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
            if not system.is_multiple_os_detected(self):
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

    def get_os_family_for_node(self, host):
        node_context = self.context['nodes'].get(host)
        if not node_context or not node_context.get('os', {}).get('family'):
            raise Exception('Node %s do not contain necessary context data' % host)
        return node_context['os']['family']

    def get_associations_for_node(self, host):
        node_os_family = self.get_os_family_for_node(host)
        return self.get_associations_for_os(node_os_family)

    def cache_package_versions(self):
        detected_packages = packages.detect_installed_packages_version_groups(self.nodes['all'].get_unchanged_nodes().get_online_nodes())
        if self.inventory['services']['packages']['associations'].get('debian'):
            del self.inventory['services']['packages']['associations']['debian']
        if self.inventory['services']['packages']['associations'].get('rhel'):
            del self.inventory['services']['packages']['associations']['rhel']
        if self.inventory['services']['packages']['associations'].get('rhel8'):
            del self.inventory['services']['packages']['associations']['rhel8']
        for association_name, associated_params in self.inventory['services']['packages']['associations'].items():
            associated_packages = associated_params.get('package_name', [])
            packages_list = []
            final_packages_list = []
            if isinstance(associated_packages, str):
                packages_list.append(associated_packages)
            else:
                packages_list = packages_list + associated_packages
            for package in packages_list:
                detected_package_versions = list(detected_packages[package].keys())
                for version in detected_package_versions:
                    if "not installed" in version:
                        # if not installed somewhere - just skip
                        final_packages_list.append(package)
                        continue
                if len(detected_package_versions) == 1:
                    final_packages_list.append(detected_package_versions[0])
                else:
                    # if detected multiple versions, then such broken package should be skipped
                    final_packages_list.append(package)
            # if non-multiple value, then convert to simple string
            if len(final_packages_list) == 1:
                final_packages_list = final_packages_list[0]
            associated_params['package_name'] = final_packages_list
        # packages from direct installation section
        if self.inventory['services']['packages']['install']:
            final_packages_list = []
            for package in self.inventory['services']['packages']['install']['include']:
                detected_package_versions = list(detected_packages[package].keys())
                for version in detected_package_versions:
                    if "not installed" in version:
                        # if not installed somewhere - just skip
                        final_packages_list.append(package)
                        continue
                if len(detected_package_versions) == 1:
                    final_packages_list.append(detected_package_versions[0])
                else:
                    # if detected multiple versions, then such broken package should be skipped
                    final_packages_list.append(package)
            self.inventory['services']['packages']['install']['include'] = final_packages_list
        return detected_packages

    def finish(self):
        self.gather_facts('after')
        # TODO: rewrite the following lines as deenrichment functions like common enrichment mechanism
        from kubetool.procedures import remove_node
        prepared_inventory = remove_node.remove_node_finalize_inventory(self, self.inventory)
        prepared_inventory = defaults.prepare_for_dump(prepared_inventory, copy=False)
        prepared_inventory = self.escape_jinja_characters_for_inventory(prepared_inventory)
        utils.dump_file(self, yaml.dump(prepared_inventory), "cluster_finalized.yaml")

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

from kubetool import system, packages
from kubetool.core import defaults, flow, utils
