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

import contextlib
import io
import random
import unittest

from kubemarine import demo
from kubemarine.core import flow
from kubemarine.core.cluster import EnrichmentStage
from kubemarine.procedures import do


class DoTest(unittest.TestCase):
    def test_command_single_master(self):
        inventory = {
            'unsupported': True,
            'nodes': [{
                # pylint: disable-next=implicit-str-concat
                'roles': ['m''a''s''t''e''r'],
                'internal_address': '1.1.1.1',
                'keyfile': '/dev/null'
            }]
        }
        context = do.create_context(['--', 'cat', '/etc/kubemarine/procedures/latest_dump/version'])
        resources = demo.new_resources(inventory, context=context)

        results = demo.create_hosts_result(['1.1.1.1'], stdout='v0.28.0\n', hide=False)
        resources.fake_shell.add(results, 'sudo', ['cat /etc/kubemarine/procedures/latest_dump/version'])

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            flow.ActionsFlow([do.CLIAction(context)]).run_flow(resources, print_summary=False)

        self.assertEqual('v0.28.0\n', buf.getvalue(), "Unexpected stdout output")

        cluster = resources.cluster(EnrichmentStage.LIGHT)
        self.assertEqual(['master'], cluster.inventory['nodes'][0]['roles'])
        self.assertEqual('control-plane-1', cluster.make_group_from_roles(['control-plane', 'master']).get_node_name())

    def test_command_run_any_node(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        hosts = [node['address'] for node in inventory['nodes']]
        context = do.create_context(['--', 'whoami'])
        resources = demo.new_resources(inventory, context=context)

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
            if node['name'] in ('worker-1', 'worker-2') or bool(set(node['roles']) & {'balancer', 'control-plane'})
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
                               or bool(set(node['roles']) & {'balancer', 'control-plane'}))
            if expected_called:
                expected_result[host] = results[host]
            self.assertEqual(expected_called, resources.fake_shell.is_called(node['address'], 'sudo', ['whoami']),
                             f"Command should be{'' if expected_called else ' not'} run on node {node['name']}")

        expected_result = demo.create_nodegroup_result_by_hosts(resources.cluster_if_initialized(), results)
        self.assertEqual(f"{expected_result}\n", buf.getvalue(), "Unexpected stdout output")


if __name__ == '__main__':
    unittest.main()
