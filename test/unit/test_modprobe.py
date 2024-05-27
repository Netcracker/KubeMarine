# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import re
import unittest
from typing import Set, Tuple, List

from kubemarine import demo, modprobe, packages
from kubemarine.core.group import NodeGroup


def actual_kernel_modules(node: NodeGroup) -> List[str]:
    config = modprobe.generate_config(node)
    return [] if not config else config.rstrip('\n').split('\n')


class ModulesEnrichment(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='22.04')
        self.inventory['services'].setdefault('modprobe', {})['debian'] = []

    def new_cluster(self) -> demo.FakeKubernetesCluster:
        return demo.new_cluster(self.inventory, nodes_context=self.nodes_context)

    def test_generate_config_all_nodes_simple_format(self):
        self.inventory['services']['modprobe']['debian'] = ['custom_module']
        cluster = self.new_cluster()
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_all_nodes_extended_format(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module'}
        ]
        cluster = self.new_cluster()
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_specific_group(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'groups': ['control-plane']}
        ]
        cluster = self.new_cluster()
        self.assertEqual({'control-plane-1'},
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_specific_nodes(self):
        specific_nodes = ['balancer-1', 'worker-1']
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'nodes': specific_nodes}
        ]
        cluster = self.new_cluster()
        self.assertEqual(set(specific_nodes),
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_groups_nodes(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'groups': ['worker'], 'nodes': ['balancer-1']}
        ]
        cluster = self.new_cluster()
        self.assertEqual({'balancer-1', 'worker-1'},
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_unknown_nodes(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'nodes': ['unknown-node']}
        ]
        cluster = self.new_cluster()
        self.assertEqual(set(),
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_parameter_not_install(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'install': False}
        ]
        cluster = self.new_cluster()
        self.assertEqual(set(),
                         self._nodes_having_modules(cluster, 'custom_module'))

    def test_generate_config_blank_module_simple_format(self):
        self.inventory['services']['modprobe']['debian'] = [
            '  '
        ]
        cluster = self.new_cluster()
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertEqual('', modprobe.generate_config(node))

    def test_error_blank_module_extended_format(self):
        self.inventory['services']['modprobe']['debian'] = [
            '  ',
            {'modulename': '  '}
        ]
        with self.assertRaisesRegex(Exception, re.escape(modprobe.ERROR_BLANK_MODULE.format(
                path="['services']['modprobe']['debian'][1]['modulename']"))):
            self.new_cluster()

    def test_error_duplicate_modules(self):
        self.inventory['services']['modprobe']['debian'] = [
            'custom_module',
            {'modulename': 'custom_module', 'install': False}
        ]
        with self.assertRaisesRegex(Exception, re.escape(modprobe.ERROR_DUPLICATE_MODULE.format(
                module_name="custom_module"))):
            self.new_cluster()

    def test_error_invalid_boolean_value_simple_format(self):
        self.inventory['services']['modprobe']['debian'] = [
            {'modulename': 'custom_module', 'install': 'test'}
        ]
        with self.assertRaisesRegex(Exception, re.escape("invalid truth value 'test' "
                                                         "in section ['services']['modprobe']['debian'][0]['install']")):
            self.new_cluster()

    def test_multiple_os_family_merge(self):
        supported_os_families = list(packages.get_associations_os_family_keys())
        self.inventory = demo.generate_inventory(control_plane=len(supported_os_families))
        self.nodes_context = demo.generate_nodes_context(self.inventory)

        control_plane_i = 0
        for node in self.inventory['nodes']:
            if 'control-plane' not in node['roles']:
                continue

            os_family = supported_os_families[control_plane_i]
            os_name, os_version = self._get_os_context(os_family)
            self.nodes_context[node['address']] = demo.generate_node_context(os_name=os_name, os_version=os_version)

            control_plane_i += 1

        os_family_i = random.randrange(len(supported_os_families))
        merge_os_family = supported_os_families[os_family_i]

        self.inventory['services'].setdefault('modprobe', {})[merge_os_family] = [
            {'<<': 'merge'},
            'custom_module',
        ]

        cluster = self.new_cluster()

        for i, control_plane in enumerate(cluster.nodes['control-plane'].get_ordered_members_list()):
            expected_modules_list = ['br_netfilter', 'nf_conntrack']
            if i == os_family_i:
                expected_modules_list += ['custom_module']

            actual_modules_list = actual_kernel_modules(control_plane)
            self.assertEqual(expected_modules_list, actual_modules_list)

    def test_default_enrichment(self):
        for os_family in packages.get_associations_os_family_keys():
            with self.subTest(os_family):
                self.inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
                os_name, os_version = self._get_os_context(os_family)
                self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)

                cluster = self.new_cluster()

                for node in cluster.nodes['all'].get_ordered_members_list():
                    if 'balancer' in node.get_config()['roles']:
                        expected_modules_list = []
                    else:
                        expected_modules_list = ['br_netfilter', 'nf_conntrack']

                    actual_modules_list = actual_kernel_modules(node)
                    self.assertEqual(expected_modules_list, actual_modules_list)

    def test_ipv6_default_enrichment(self):
        for os_family in packages.get_associations_os_family_keys():
            with self.subTest(os_family):
                self.inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
                os_name, os_version = self._get_os_context(os_family)
                self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
                for i, node in enumerate(self.inventory['nodes']):
                    node['internal_address'] = f'2001::{i + 1}'

                cluster = self.new_cluster()

                if os_family == 'rhel':
                    expected_all_modules_list = [
                        'br_netfilter',
                        'nf_conntrack_ipv6',
                        'ip6table_filter',
                        'nf_nat_masquerade_ipv6',
                        'nf_reject_ipv6',
                        'nf_defrag_ipv6',
                    ]
                else:
                    expected_all_modules_list = [
                        'br_netfilter',
                        'nf_conntrack',
                        'ip6table_filter',
                        'nf_nat',
                        'nf_reject_ipv6',
                        'nf_defrag_ipv6',
                    ]

                kubernetes_only_modules_list = [
                    'br_netfilter',
                    'nf_conntrack',
                ]

                for node in cluster.nodes['all'].get_ordered_members_list():
                    expected_modules_list = list(expected_all_modules_list)
                    if 'balancer' in node.get_config()['roles']:
                        for module_name in kubernetes_only_modules_list:
                            if module_name in expected_modules_list:
                                expected_modules_list.remove(module_name)

                    actual_modules_list = actual_kernel_modules(node)
                    self.assertEqual(expected_modules_list, actual_modules_list)

    def _get_os_context(self, os_family: str) -> Tuple[str, str]:
        return {
            'debian': ('ubuntu', '22.04'),
            'rhel': ('centos', '7.9'),
            'rhel8': ('rhel', '8.7'),
            'rhel9': ('rhel', '9.2')
        }[os_family]

    def _nodes_having_modules(self, cluster: demo.FakeKubernetesCluster, module_name: str) -> Set[str]:
        return {node.get_node_name() for node in cluster.nodes['all'].get_ordered_members_list()
                if module_name in actual_kernel_modules(node)}


if __name__ == '__main__':
    unittest.main()
