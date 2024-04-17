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
from kubemarine.core.cluster import EnrichmentStage
from kubemarine.demo import FakeKubernetesCluster


def get_os_family(cluster: FakeKubernetesCluster):
    return cluster.get_os_family()


class KubernetesClusterTest(unittest.TestCase):

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
        nodes_context = self._nodes_context_one_different_os(inventory, host_different_os)
        cluster = demo.new_cluster(inventory, context=context, nodes_context=nodes_context)
        self.assertEqual('multiple', get_os_family(cluster),
                         msg="One node has different OS family and thus global OS family should be 'multiple'")

    def test_add_node_different_os_get_os_family_multiple(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        host_different_os = inventory['nodes'][0]['address']
        nodes_context = self._nodes_context_one_different_os(inventory, host_different_os)
        add_node = demo.generate_procedure_inventory('add_node')
        add_node['nodes'] = [inventory['nodes'].pop(0)]
        cluster = demo.new_cluster(inventory, procedure_inventory=add_node, context=context,
                                   nodes_context=nodes_context)
        self.assertEqual('multiple', get_os_family(cluster),
                         msg="One node has different OS family and thus global OS family should be 'multiple'")

    def test_remove_node_different_os_get_os_family_single(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        host_different_os = inventory['nodes'][0]['address']
        nodes_context = self._nodes_context_one_different_os(inventory, host_different_os)
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [{"name": inventory["nodes"][0]["name"]}]
        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context,
                                   nodes_context=nodes_context)
        self.assertEqual('debian', get_os_family(cluster),
                         msg="The only node with different OS family is removed, "
                             "and global OS family should the specific remained")

    def test_remove_node_different_os_get_package_associations(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        host_different_os = inventory['nodes'][0]['address']
        remained_host = inventory['nodes'][1]['address']
        nodes_context = self._nodes_context_one_different_os(inventory, host_different_os)
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [{"name": inventory["nodes"][0]["name"]}]
        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context,
                                   nodes_context=nodes_context)
        self.assertEqual('conntrack-tools',
                         cluster.get_package_association_for_node(host_different_os, 'conntrack', 'package_name'),
                         msg="Unexpected package associations of node to remove")
        self.assertEqual('conntrack',
                         cluster.get_package_association_for_node(remained_host, 'conntrack', 'package_name'),
                         msg="Unexpected package associations of remained node")

    def test_upgrade_get_redefined_package_associations(self):
        before, after = 'v1.27.8', 'v1.28.8'
        context = demo.create_silent_context(['fake.yaml'], procedure='upgrade')
        context['upgrade_step'] = 0

        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services']['kubeadm'] = {
            'kubernetesVersion': before
        }
        upgrade = demo.generate_procedure_inventory('upgrade')
        upgrade['upgrade_plan'] = [after]
        upgrade.setdefault(after, {})['packages'] = {
            'associations': {'containerd': {'package_name': 'containerd_new'}}
        }
        cluster = demo.new_cluster(inventory, procedure_inventory=upgrade, context=context)
        self.assertEqual('containerd_new',
                         cluster.get_package_association_for_node(cluster.nodes['all'].get_any_member().get_host(),
                                                                  'containerd', 'package_name'),
                         msg="Package associations are not redefined")

    def _nodes_context_one_different_os(self, inventory, host_different_os):
        nodes_context = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='20.04')
        nodes_context[host_different_os]['os'] = {
            'name': 'centos',
            'family': 'rhel',
            'version': '7.9'
        }
        return nodes_context


class LightClusterTest(unittest.TestCase):
    def test_add_node_connection_pool(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        all_hosts = [node['address'] for node in inventory['nodes']]
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        add_node = demo.generate_procedure_inventory('add_node')
        add_node['nodes'] = [inventory['nodes'].pop(0)]

        res = demo.new_resources(inventory, procedure_inventory=add_node, context=context)
        connection_pool = res.cluster(EnrichmentStage.LIGHT).connection_pool

        for host in all_hosts:
            self.assertEqual(host, connection_pool.get_connection(host).host)

    def test_remove_node_connection_pool(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        all_hosts = [node['address'] for node in inventory['nodes']]
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [{"name": inventory["nodes"][0]["name"]}]

        res = demo.new_resources(inventory, procedure_inventory=remove_node, context=context)
        connection_pool = res.cluster(EnrichmentStage.LIGHT).connection_pool

        for host in all_hosts:
            self.assertEqual(host, connection_pool.get_connection(host).host)

    def test_add_node_get_nodes(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        add_node = demo.generate_procedure_inventory('add_node')
        add_node['nodes'] = [inventory['nodes'].pop(1)]

        all_hosts = [node['address'] for node in inventory['nodes']]
        all_hosts.append(add_node['nodes'][0]['address'])

        res = demo.new_resources(inventory, procedure_inventory=add_node, context=context)
        cluster = res.cluster(EnrichmentStage.LIGHT)

        self.assertEqual([], cluster.get_nodes_for_removal().get_hosts())
        self.assertEqual(all_hosts[-1:], cluster.get_new_nodes().get_hosts())
        self.assertEqual(all_hosts[-1:], cluster.get_changed_nodes().get_hosts())
        self.assertEqual(all_hosts[:2], cluster.get_unchanged_nodes().get_hosts())

        self.assertEqual(all_hosts, cluster.nodes['control-plane'].get_hosts())
        self.assertEqual(all_hosts[:2], cluster.previous_nodes['control-plane'].get_hosts())

        self.assertEqual(all_hosts[-1:], cluster.get_new_nodes().having_roles(['control-plane']).get_hosts())
        self.assertEqual(all_hosts[-1:], [node.get_host() for node in cluster.get_new_nodes().get_ordered_members_list()])

    def test_remove_node_get_nodes(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        all_hosts = [node['address'] for node in inventory['nodes']]
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [{"name": inventory["nodes"][0]["name"]}]

        res = demo.new_resources(inventory, procedure_inventory=remove_node, context=context)
        cluster = res.cluster(EnrichmentStage.LIGHT)

        self.assertEqual(all_hosts[:1], cluster.get_nodes_for_removal().get_hosts())
        self.assertEqual([], cluster.get_new_nodes().get_hosts())
        self.assertEqual(all_hosts[:1], cluster.get_changed_nodes().get_hosts())
        self.assertEqual(all_hosts[1:], cluster.get_unchanged_nodes().get_hosts())

        self.assertEqual(all_hosts[1:], cluster.nodes['control-plane'].get_hosts())
        self.assertEqual(all_hosts, cluster.previous_nodes['control-plane'].get_hosts())

        self.assertEqual(all_hosts[:1], cluster.get_nodes_for_removal().having_roles(['control-plane']).get_hosts())
        self.assertEqual(all_hosts[:1],
                         [node.get_host() for node in cluster.get_nodes_for_removal().get_ordered_members_list()])


if __name__ == '__main__':
    unittest.main()
