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

import os.path
import tempfile
import unittest

from kubemarine import demo, kubernetes
from kubemarine.core import flow
from kubemarine.kubernetes import components
from kubemarine.procedures.add_node import AddNodeAction
from test.unit import utils as test_utils


class EnrichmentAndFinalization(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='add_node')
        self.inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.add_node = demo.generate_procedure_inventory('add_node')
        self.add_node['nodes'] = [self.inventory['nodes'].pop(0)]

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _run_action(self) -> demo.FakeResources:
        resources = demo.FakeResources(self.context, self.inventory,
                                       procedure_inventory=self.add_node, nodes_context=self.nodes_context)
        flow.run_actions(resources, [AddNodeAction()])
        return resources

    def test_enrich_inventory_generate_ansible_add_role(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir.name, 'ansible-inventory.ini')
        args['ansible_inventory_location'] = ansible_inventory_location

        res = self._run_action()
        cluster = res.last_cluster

        self.assertTrue(os.path.exists(ansible_inventory_location),
                        "Ansible inventory was not created")

        self.assertIn('add_node', cluster.inventory['nodes'][2]['roles'],
                      "'add_node' role was not added in inventory")
        self.assertNotIn('add_node', res.stored_inventory['nodes'][2]['roles'],
                         "'add_node' role should not be in recreated inventory")

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = cluster.make_finalized_inventory()
        self.assertNotIn('add_node', finalized_inventory['nodes'][2]['roles'],
                         "'add_node' role should not be in finalized inventory")

    def test_enrich_inventory_generate_ansible_new_nodes_group(self):
        args = self.context['execution_arguments']
        args['ansible_inventory_location'] = os.path.join(self.tmpdir.name, 'ansible-inventory.ini')

        res = self._run_action()
        new_nodes = res.last_cluster.nodes['all'].get_new_nodes()
        self.assertEqual({self.add_node['nodes'][0]['address']}, new_nodes.nodes,
                         "Unexpected group with new nodes")


class RunTasks(unittest.TestCase):
    def setUp(self):
        self.inventory = {}
        self.context = {}

    def _run_tasks(self, tasks_filter: str, added_node_name: str) -> demo.FakeResources:
        context = demo.create_silent_context(
            ['fake.yaml', '--tasks', tasks_filter], procedure='add_node')

        nodes_context = demo.generate_nodes_context(self.inventory)

        added_node_idx = next(i for i, node in enumerate(self.inventory['nodes'])
                              if node['name'] == added_node_name)

        added_node = self.inventory['nodes'].pop(added_node_idx)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [added_node]

        resources = demo.FakeResources(context, self.inventory,
                                       procedure_inventory=procedure_inventory, nodes_context=nodes_context)
        flow.run_actions(resources, [AddNodeAction()])
        return resources

    def test_kubernetes_init_write_new_certificates(self):
        for new_role, expected_called in (('worker', False), ('master', True), ('balancer', True)):
            with self.subTest(f"Add: {new_role}"), \
                    test_utils.mock_call(kubernetes.join_new_control_plane), \
                    test_utils.mock_call(kubernetes.init_workers), \
                    test_utils.mock_call(kubernetes.apply_labels), \
                    test_utils.mock_call(kubernetes.apply_taints), \
                    test_utils.mock_call(kubernetes.wait_for_nodes), \
                    test_utils.mock_call(kubernetes.schedule_running_nodes_report), \
                    test_utils.mock_call(components.reconfigure_components) as run:

                self.inventory = demo.generate_inventory(balancer=2, master=2, worker=2)

                new_node_name = f'{new_role}-2'
                res = self._run_tasks('deploy.kubernetes.init', new_node_name)

                actual_called_components = run.call_args[0][1] if run.called else []
                expected_called_components = ['kube-apiserver/cert-sans'] if expected_called else []
                self.assertEqual(expected_called_components, actual_called_components,
                                 f"New certificate was {'not' if expected_called else 'unexpectedly'} written")

                if expected_called:
                    self.assertEqual(['master-1', 'master-2'], run.call_args[0][0].get_nodes_names())

                certsans = res.last_cluster.inventory['services']['kubeadm']['apiServer']['certSANs']
                self.assertEqual(expected_called, new_node_name in certsans,
                                 "New certificate should be written if and only if new cert SAN appears")


if __name__ == '__main__':
    unittest.main()
