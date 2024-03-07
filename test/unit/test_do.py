import contextlib
import io
import random
import unittest

from kubemarine import demo
from kubemarine.core import flow
from kubemarine.procedures import do


class DoTest(unittest.TestCase):
    def test_command_run_any_node(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        hosts = [node['address'] for node in inventory['nodes']]
        context = do.create_context(['--', 'whoami'])
        resources = demo.new_resources(inventory, context=context)
        # Set make_finalized_inventory=None to invoke real method making it closer to the real work
        resources.make_finalized_inventory = None

        results = demo.create_hosts_result(hosts, stdout='root\n', hide=False)
        resources.fake_shell.add(results, 'sudo', ['whoami'])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            flow.ActionsFlow([do.CLIAction(context)]).run_flow(resources, print_summary=False)

        num_called = sum(resources.fake_shell.called_times(host, 'sudo', ['whoami']) for host in hosts)
        self.assertEqual(1, num_called, "Command was not run")
        self.assertEqual('root\n', buf.getvalue(), "Unexpected stdout output")

    def test_command_called_specific_node(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        run_on = random.choice(inventory['nodes'])
        context = do.create_context(['-n', run_on['name'], '--', 'whoami'])
        resources = demo.new_resources(inventory, context=context)

        results = demo.create_hosts_result([run_on['address']], stdout='root\n', hide=False)
        resources.fake_shell.add(results, 'sudo', ['whoami'])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            flow.ActionsFlow([do.CLIAction(context)]).run_flow(resources, print_summary=False)

        for node in inventory['nodes']:
            expected_called = node is run_on
            self.assertEqual(expected_called, resources.fake_shell.is_called(node['address'], 'sudo', ['whoami']),
                             f"Command should be{'' if expected_called else ' not'} run on node {node['name']}")

        self.assertEqual('root\n', buf.getvalue(), "Unexpected stdout output")

    def test_command_called_mixed_nodes(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        context = do.create_context([
            '-n', 'worker-1,worker-2',
            '-g', 'balancer,control-plane',
            '--no_stream',
            '--', 'whoami'])
        expected_called_hosts = [
            node['address'] for node in inventory['nodes']
            if node['name'] in ('worker-1', 'worker-2') or bool(set(node['roles']) & {'balancer', 'master'})
        ]
        resources = demo.new_resources(inventory, context=context)

        results = demo.create_hosts_result(expected_called_hosts, stdout='root\n', hide=True)
        resources.fake_shell.add(results, 'sudo', ['whoami'])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            flow.ActionsFlow([do.CLIAction(context)]).run_flow(resources, print_summary=False)

        expected_result = {}
        for node in inventory['nodes']:
            host = node['address']
            expected_called = (node['name'] in ('worker-1', 'worker-2')
                               or bool(set(node['roles']) & {'balancer', 'master'}))
            if expected_called:
                expected_result[host] = results[host]
            self.assertEqual(expected_called, resources.fake_shell.is_called(node['address'], 'sudo', ['whoami']),
                             f"Command should be{'' if expected_called else ' not'} run on node {node['name']}")

        expected_result = demo.create_nodegroup_result_by_hosts(resources.cluster_if_initialized(), results)
        self.assertEqual(f"{expected_result}\n", buf.getvalue(), "Unexpected stdout output")


if __name__ == '__main__':
    unittest.main()
