import unittest

from kubemarine import demo
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources


class FakeResources(demo.FakeResources):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recreated_inventory = None

    def recreate_inventory(self):
        self.recreated_inventory = self._formatted_inventory


class RunActionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.context = demo.create_silent_context(flow.new_common_parser("Help text"), [])
        self.context['preserve_inventory'] = True
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        self.cluster: demo.FakeKubernetesCluster = demo.new_cluster(self.inventory, context=self.context)

    def test_patch_inventory(self):
        class TheAction(Action):
            def run(self, res: DynamicResources):
                res.formatted_inventory()['p2'] = 'v2'

            def __init__(self):
                super().__init__('test', recreate_inventory=True)

        res = FakeResources(self.context, {"p1": "v1"})
        flow.run_actions(self.context, [TheAction()], resources=res, print_final_message=False)
        self.assertEqual(res.recreated_inventory, {"p1": "v1", "p2": "v2"})

    def test_patch_cluster(self):
        class TheAction(Action):
            def run(self, res: DynamicResources):
                res.cluster().nodes['all'].sudo('whoami')

            def __init__(self):
                super().__init__('test')

        nodes = self.cluster.nodes['all']
        result = demo.create_nodegroup_result(nodes, stdout='root')
        fake_shell = self.cluster.fake_shell
        fake_shell.add(result, 'sudo', ['whoami'])

        self.assertFalse('successfully_performed' in self.cluster.context)

        res = FakeResources(self.context, self.inventory, cluster=self.cluster)
        flow.run_actions(self.context, [TheAction()], resources=res, print_final_message=False)
        for host in nodes.get_hosts():
            history = fake_shell.history_find(host, 'sudo', ['whoami'])
            self.assertTrue(len(history) == 1 and history[0]["used_times"] == 1)

        self.assertEqual(['test'], self.cluster.context['successfully_performed'])
