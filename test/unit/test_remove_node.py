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

import json
import os
import unittest
from typing import List, Dict
from test.unit import utils as test_utils

from kubemarine import demo
from kubemarine.core import utils, flow
from kubemarine.procedures import remove_node, install


class EnrichmentAndFinalization(test_utils.CommonTest):
    def setUp(self) -> None:
        self.context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='remove_node')

        self.nodes_context = {}
        self.inventory = {}
        self.remove_node = demo.generate_procedure_inventory('remove_node')

    def _generate_inventory(self, scheme: Dict[str, demo._ROLE_SPEC]) -> dict:
        self.inventory = demo.generate_inventory(**scheme)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        return self.inventory

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.remove_node,
                                        nodes_context=self.nodes_context)

    def _new_cluster(self) -> demo.FakeKubernetesCluster:
        return self._new_resources().cluster()

    def _run(self) -> demo.FakeResources:
        resources = self._new_resources()
        flow.run_actions(resources, [remove_node.RemoveNodeAction()])
        return resources

    def test_previous_nodes(self):
        self._generate_inventory(demo.MINIHA_KEEPALIVED)
        hosts = [node['address'] for node in self.inventory['nodes']]
        node_name_remove = self.inventory['nodes'][0]['name']
        self.remove_node['nodes'] = [{'name': node_name_remove}]

        cluster = self._new_cluster()
        self.assertIs(cluster, cluster.previous_nodes['all'].cluster,
                      "Cluster of previous group should be the same as the main cluster")

        self.assertEqual(hosts, cluster.previous_nodes['all'].get_hosts())

        self.assertIs(cluster, cluster.get_nodes_for_removal().cluster)
        self.assertEqual([node_name_remove], cluster.get_nodes_for_removal().get_nodes_names())

    def test_allow_omitted_name(self):
        self._generate_inventory(demo.MINIHA_KEEPALIVED)
        for node in self.inventory['nodes']:
            del node['name']
        self.remove_node['nodes'] = [{'name': 'control-plane-2'}]

        cluster = self._new_cluster()

        nodes_for_removal = cluster.get_nodes_for_removal()
        self.assertEqual(['control-plane-2'], nodes_for_removal.get_nodes_names())

        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        self.assertEqual(['control-plane-1', 'control-plane-3'], [node['name'] for node in finalized_inventory['nodes']])

        self.assertEqual(['control-plane-1', 'control-plane-3'], [node['name'] for node in cluster.formatted_inventory['nodes']])

    @test_utils.temporary_directory
    def test_ansible_inventory_no_removed_node(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir, 'ansible-inventory.ini')
        args['ansible_inventory_location'] = ansible_inventory_location

        self._generate_inventory(demo.MINIHA_KEEPALIVED)
        node_name_remove = self.inventory['nodes'][0]['name']
        self.remove_node['nodes'] = [{'name': node_name_remove}]

        self._run()
        self.assertTrue(os.path.exists(ansible_inventory_location),
                        "Ansible inventory was not created")

        ansible_inventory = utils.read_external(ansible_inventory_location)
        for node in self.inventory['nodes']:
            should_present = node['name'] != node_name_remove
            self.assertEqual(should_present, node['name'] in ansible_inventory)

    def test_remove_turned_off_balancer_maintenance_mode(self):
        scheme = {'balancer': 3, 'control_plane': 3, 'worker': 3, 'keepalived': 1, 'haproxy_mntc': 1}
        self._generate_inventory(scheme)

        balancers = [node for node in self.inventory['nodes'] if 'balancer' in node['roles']]
        self.nodes_context[balancers[0]['address']] = demo.generate_node_context(online=False)
        self.remove_node['nodes'] = [balancers[0], balancers[1]]
        removed_balancer_names = [node['name'] for node in self.remove_node['nodes']]
        online_balancer_names = [balancers[1]['name']]

        cluster = self._new_cluster()

        self.assertEqual(removed_balancer_names, cluster.get_nodes_for_removal().get_nodes_names(),
                         "Unexpected nodes for removal")

        for role in ('balancer', 'keepalived'):
            self.assertEqual([balancers[2]['name']], cluster.make_group_from_roles([role]).get_nodes_names(),
                             f"Unexpected final nodes for {role!r} group")

            self.assertEqual(removed_balancer_names, cluster.get_nodes_for_removal().having_roles([role]).get_nodes_names(),
                             f"Node for removal should present among {role!r} group to be removed")

            self.assertEqual(online_balancer_names, remove_node.get_active_nodes(role, cluster).get_nodes_names(),
                             f"Node for removal should present among {role!r} active group")

        self.assertEqual([balancers[2]['name']], install.get_keepalived_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure keepalived")
        self.assertEqual([], install.get_haproxy_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure haproxy")

    @test_utils.temporary_directory
    def test_enrich_certsans_with_custom(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir, 'ansible-inventory.ini')
        args['ansible_inventory_location'] = ansible_inventory_location

        self._generate_inventory(demo.MINIHA_KEEPALIVED)
        self.remove_node['nodes'] = [self.inventory['nodes'][0], self.inventory['nodes'][1]]
        self.inventory['services'].setdefault('kubeadm', {}).setdefault('apiServer', {})['certSANs'] = [
            self.remove_node['nodes'][0]['name'], 'custom'
        ]

        def check_enriched_certsans(certsans: List[str]):
            self.assertIn(self.inventory['nodes'][0]['name'], certsans)
            self.assertNotIn(self.inventory['nodes'][1]['name'], certsans)
            self.assertIn(self.inventory['nodes'][2]['name'], certsans)
            self.assertIn('custom', certsans)

        cluster = self._new_cluster()
        certsans = cluster.inventory["services"]["kubeadm"]['apiServer']['certSANs']
        check_enriched_certsans(certsans)

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        certsans = finalized_inventory["services"]["kubeadm"]['apiServer']['certSANs']
        check_enriched_certsans(certsans)

        certsans = cluster.formatted_inventory["services"]["kubeadm"]['apiServer']['certSANs']
        self.assertIn(self.inventory['nodes'][0]['name'], certsans)
        self.assertNotIn(self.inventory['nodes'][1]['name'], certsans)
        self.assertNotIn(self.inventory['nodes'][2]['name'], certsans)
        self.assertIn('custom', certsans)

        ansible_inventory = utils.read_external(ansible_inventory_location)
        kubeadm_apiserver = next(filter(lambda l: 'kubeadm_apiServer=' in l, ansible_inventory.split('\n')))
        certsans = json.loads(kubeadm_apiserver[len('kubeadm_apiServer='):])['certSANs']
        check_enriched_certsans(certsans)


if __name__ == '__main__':
    unittest.main()
