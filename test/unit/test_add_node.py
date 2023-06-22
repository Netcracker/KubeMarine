import os.path
import tempfile
import unittest

from kubemarine import demo
from kubemarine.core import flow
from kubemarine.procedures.add_node import AddNodeAction
from test.unit import utils as test_utils


class EnrichmentAndFinalization(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='add_node',
                                                  parser=flow.new_procedure_parser("Help text"))
        self.inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.add_node = {'nodes': [self.inventory['nodes'].pop(0)]}

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


if __name__ == '__main__':
    unittest.main()
