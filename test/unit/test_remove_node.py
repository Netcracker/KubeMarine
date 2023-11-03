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
import tempfile
import unittest
from typing import List, Dict

from kubemarine import demo
from kubemarine.core import flow, utils
from kubemarine.procedures import remove_node
from test.unit import utils as test_utils


class EnrichmentAndFinalization(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='remove_node')

        self.nodes_context = {}
        self.inventory = {}
        self.remove_node = demo.generate_procedure_inventory('remove_node')

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _generate_inventory(self, scheme: Dict[str, demo._ROLE_SPEC]) -> dict:
        self.inventory = demo.generate_inventory(**scheme)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        return self.inventory

    def _run(self) -> demo.FakeResources:
        resources = demo.FakeResources(self.context, self.inventory,
                                       procedure_inventory=self.remove_node,
                                       nodes_context=self.nodes_context)
        flow.ActionsFlow([remove_node.RemoveNodeAction()]).run_flow(resources)
        return resources

    def test_allow_omitted_name(self):
        self._generate_inventory(demo.MINIHA_KEEPALIVED)
        for node in self.inventory['nodes']:
            del node['name']
        self.remove_node['nodes'] = [{'name': 'control-plane-2'}]

        resources = self._run()
        cluster = resources.last_cluster

        nodes_for_removal = cluster.nodes['all'].get_nodes_for_removal()
        self.assertEqual(['control-plane-2'], nodes_for_removal.get_nodes_names())

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = cluster.make_finalized_inventory()

        self.assertEqual(['control-plane-1', 'control-plane-3'], [node['name'] for node in finalized_inventory['nodes']])

        self.assertEqual(['control-plane-1', 'control-plane-3'], [node['name'] for node in resources.stored_inventory['nodes']])

    def test_ansible_inventory_no_removed_node(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir.name, 'ansible-inventory.ini')
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
        scheme = {'balancer': 3, 'master': 3, 'worker': 3, 'keepalived': 1, 'haproxy_mntc': 1}
        self._generate_inventory(scheme)

        balancers = [node for node in self.inventory['nodes'] if 'balancer' in node['roles']]
        balancer_names = [node['name'] for node in balancers]
        self.nodes_context[balancers[0]['address']] = {'access': {
            'online': False,
            'accessible': False,
            'sudo': 'No'
        }}
        self.remove_node['nodes'] = [balancers[0], balancers[1]]
        removed_balancer_names = [node['name'] for node in self.remove_node['nodes']]
        online_balancer_names = [balancers[1]['name']]

        cluster = self._run().last_cluster

        self.assertEqual(removed_balancer_names, cluster.nodes['all'].get_nodes_for_removal().get_nodes_names(),
                         "Unexpected nodes for removal")

        for role in ('balancer', 'keepalived'):
            self.assertEqual(balancer_names, cluster.make_group_from_roles([role]).get_nodes_names(),
                             f"Node for removal should be present among {role!r} group")

            self.assertEqual(online_balancer_names, remove_node.get_active_nodes(role, cluster).get_nodes_names(),
                             f"Node for removal should be present among {role!r} group")

    def test_enrich_certsans_with_custom(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir.name, 'ansible-inventory.ini')
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

        resources = self._run()
        cluster = resources.last_cluster
        certsans = cluster.inventory["services"]["kubeadm"]['apiServer']['certSANs']
        check_enriched_certsans(certsans)

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = cluster.make_finalized_inventory()
        certsans = finalized_inventory["services"]["kubeadm"]['apiServer']['certSANs']
        check_enriched_certsans(certsans)

        certsans = resources.stored_inventory["services"]["kubeadm"]['apiServer']['certSANs']
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
