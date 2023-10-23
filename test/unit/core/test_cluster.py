#!/usr/bin/env python3
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


import unittest

from kubemarine import demo
from kubemarine.demo import FakeKubernetesCluster


def get_os_family(cluster: FakeKubernetesCluster):
    return cluster.get_os_family()


class KubernetesClusterTest(unittest.TestCase):

    # TODO: add more tests

    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_make_group_from_strs(self):
        expected_group = self.cluster.nodes['master']
        actual_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3', '10.101.1.4'])
        self.assertEqual(expected_group, actual_group, msg="Created group is not equivalent to master group")

    def test_make_group_from_nodegroups(self):
        masters = self.cluster.nodes['master']
        balancer = self.cluster.nodes['balancer']
        expected_group = balancer.include_group(masters)
        actual_group = self.cluster.make_group([balancer, masters])
        self.assertEqual(expected_group, actual_group, msg="Created group is not equivalent to merged group")

    def test_make_group_from_mixed_types(self):
        actual_group = self.cluster.make_group([
            '10.101.1.1',
            self.cluster.nodes['master'],
            '10.101.1.5',
            '10.101.1.6',
            '10.101.1.7'
        ])
        self.assertEqual(self.cluster.nodes['all'], actual_group,
                         msg="Created group is not equivalent to all nodes group")

    def test_get_os_family(self):
        cluster = demo.new_cluster(demo.generate_inventory(**demo.MINIHA_KEEPALIVED))
        self.assertEqual('rhel', get_os_family(cluster),
                         msg="Demo cluster should be created with 'rhel' OS family by default")

    def test_get_os_family_multiple(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context()
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        cluster = demo.new_cluster(inventory, context=context)
        self.assertEqual('multiple', get_os_family(cluster),
                         msg="One node has different OS family and thus global OS family should be 'multiple'")

    def test_add_node_different_os_get_os_family_multiple(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        add_node = demo.generate_procedure_inventory('add_node')
        add_node['nodes'] = [inventory['nodes'].pop(0)]
        cluster = demo.new_cluster(inventory, procedure_inventory=add_node, context=context)
        self.assertEqual('multiple', get_os_family(cluster),
                         msg="One node has different OS family and thus global OS family should be 'multiple'")

    def test_remove_node_different_os_get_os_family_single(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [{"name": inventory["nodes"][0]["name"]}]
        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context)
        self.assertEqual('debian', get_os_family(cluster),
                         msg="One node has different OS family and thus global OS family should be 'multiple'")

    def _nodes_context_one_different_os(self, inventory, host_different_os):
        nodes_context = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='20.04')
        nodes_context[host_different_os]['os'] = {
            'name': 'centos',
            'family': 'rhel',
            'version': '7.9'
        }
        return nodes_context


if __name__ == '__main__':
    unittest.main()
