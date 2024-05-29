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
import io
import os
import tempfile
import unittest
import random

from kubemarine import demo
from kubemarine.core.group import GroupResultException, CollectorCallback
from kubemarine.demo import FakeKubernetesCluster


class TestGroupCreation(unittest.TestCase):

    # Test should from the following cluster:
    # control-plane-1 roles: [control-plane, worker]
    # worker-1 roles: [worker]
    # Get only node with single worker role using filter lambda function
    def test_new_group_from_lambda_filter(self):
        multirole_inventory = demo.generate_inventory(balancer=0, control_plane=1, worker=['control-plane-1', 'worker-1'])
        cluster = demo.new_cluster(multirole_inventory)

        expected_group = cluster.make_group(cluster.nodes['worker'].get_hosts()[1:])
        filtered_group = cluster.nodes['worker'].new_group(apply_filter=lambda node: 'control-plane' not in node['roles'])

        self.assertEqual(expected_group.nodes, filtered_group.nodes, msg="Filtered groups do not match")

    def test_exclude_group(self):
        inventory = demo.generate_inventory(balancer=2, control_plane=2, worker=0)
        cluster = demo.new_cluster(inventory)

        result_group = cluster.nodes['all'].exclude_group(cluster.nodes['balancer'])

        self.assertEqual(cluster.nodes['control-plane'].nodes, result_group.nodes, msg="Final groups do not match")

    def test_exclude_group_2(self):
        multirole_inventory = demo.generate_inventory(balancer=0, control_plane=1, worker=['control-plane-1', 'worker-1'])
        cluster = demo.new_cluster(multirole_inventory)

        expected_group = cluster.make_group(cluster.nodes['worker'].get_hosts()[1:])
        result_group = cluster.nodes['worker'].exclude_group(cluster.nodes['control-plane'])

        self.assertEqual(expected_group.nodes, result_group.nodes, msg="Final groups do not match")

    def test_include_group(self):
        inventory = demo.generate_inventory(balancer=2, control_plane=2, worker=0)
        cluster = demo.new_cluster(inventory)

        result_group = cluster.nodes['balancer'].include_group(cluster.nodes['control-plane'])

        self.assertEqual(cluster.nodes['all'].nodes, result_group.nodes, msg="Final groups do not match")


class TestGroupCall(unittest.TestCase):
    cluster: FakeKubernetesCluster = None

    @classmethod
    def setUpClass(cls):
        cls.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def tearDown(self):
        TestGroupCall.cluster.fake_shell.reset()
        TestGroupCall.cluster.fake_fs.reset()

    def test_run_empty_group(self):
        # bug reproduces inside _do(), that is why it is necessary to use real cluster
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))
        empty_group = cluster.nodes["worker"].new_group(apply_filter=lambda node: 'xxx' in node['roles'])
        # if there no nodes in empty group - an exception should not be produced - empty result should be returned
        empty_group.run('whoami')

    def test_GroupException_one_node_failed(self):
        all_nodes = TestGroupCall.cluster.nodes["all"]
        results = demo.create_hosts_result(all_nodes.get_hosts(), stdout='example result')
        results[random.choice(all_nodes.get_hosts())] = Exception('Some error')

        TestGroupCall.cluster.fake_shell.add(results, "run", ['some command'])

        exception = None
        try:
            all_nodes.run('some command')
        except GroupResultException as e:
            exception = e

        self.assertIsNotNone(exception, msg="GroupResultException should be raised")
        nested_exc = 0
        for _, result in exception.result.items():
            if isinstance(result, Exception):
                nested_exc += 1
                self.assertEqual('Some error', result.args[0], msg="Unexpected exception message")

        self.assertEqual(1, nested_exc, msg="One wrapped exception should happen")

    def test_run_with_callback(self):
        all_nodes = self.cluster.nodes["all"]
        results = demo.create_hosts_result(all_nodes.get_hosts(), stdout='example result')
        self.cluster.fake_shell.add(results, "run", ['some command'])
        callback = CollectorCallback(self.cluster)
        all_nodes.run('some command', callback=callback)
        for host in all_nodes.get_hosts():
            result = callback.results.get(host, [])
            self.assertEqual(1, len(result), "Result was not collected")
            self.assertEqual('example result', result[0].stdout, "Result was not collected")

    def test_run_failed_callback_not_collected(self):
        all_nodes = self.cluster.nodes["all"]
        results = demo.create_hosts_result(all_nodes.get_hosts(), stderr='command failed', code=1)
        self.cluster.fake_shell.add(results, "run", ['some command'])
        callback = CollectorCallback(self.cluster)
        with self.assertRaises(GroupResultException):
            all_nodes.run('some command', callback=callback)
        for host in all_nodes.get_hosts():
            result = callback.results.get(host, [])
            self.assertEqual(0, len(result), "Result should be not collected")

    def test_represent_group_exception_with_hide_false(self):
        one_node = self.cluster.nodes["all"].get_first_member()
        results = demo.create_hosts_result(one_node.get_hosts(), stderr='command failed', hide=False, code=1)
        self.cluster.fake_shell.add(results, "run", ['some command'])

        exception = None
        try:
            one_node.run('some command', hide=False)
        except GroupResultException as exc:
            exception = exc

        self.assertIsNotNone(exception, "Exception was not raised")
        expected_results_str = ("""\
            10.101.1.1:
            \tEncountered a bad command exit code!
            \t
            \tCommand: 'some command'
            \t
            \tExit code: 1
            \t
            \t=== stderr ===
            \talready printed
            \t"""
                                ).replace("""\
            """, ""
                                          )
        self.assertEqual(expected_results_str, str(exception),
                         "Unexpected textual representation of remote group exception")

    def test_write_stream(self):
        expected_data = 'hello\nworld'
        self.cluster.nodes['control-plane'].put(io.StringIO(expected_data), '/tmp/test/file.txt')
        actual_data_group = self.cluster.fake_fs.read_all(self.cluster.nodes['control-plane'].get_hosts(), '/tmp/test/file.txt')

        for host, actual_data in actual_data_group.items():
            self.assertEqual(expected_data, actual_data, msg="Written and read data are not equal for node %s" % host)

    def test_write_large_stream(self):
        self.cluster.fake_fs.emulate_latency = True
        all_nodes = self.cluster.nodes["all"]
        all_nodes.put(io.StringIO('a' * 100000), '/fake/path')

        for host in all_nodes.get_hosts():
            self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))

    def test_write_large_file(self):
        self.cluster.fake_fs.emulate_latency = True
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, 'file.txt')
            with open(file, 'w', encoding='utf-8') as f:
                f.write('a' * 100000)

            all_nodes = self.cluster.nodes["all"]
            all_nodes.put(file, '/fake/path')

            for host in all_nodes.get_hosts():
                self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))

    def test_wait_commands_successful_intermediate_failed(self):
        node = self.cluster.nodes["all"].get_first_member()

        results = demo.create_hosts_result(node.get_hosts(), stdout='result1')
        TestGroupCall.cluster.fake_shell.add(results, "run", ['command1'], usage_limit=1)

        results = demo.create_hosts_result(node.get_hosts(), stderr='error2', code=1)
        TestGroupCall.cluster.fake_shell.add(results, "run", ['command2'], usage_limit=1)

        results = demo.create_hosts_result(node.get_hosts(), stdout='result2')
        TestGroupCall.cluster.fake_shell.add(results, "run", ['command2'], usage_limit=1)

        results = demo.create_hosts_result(node.get_hosts(), stdout='result3')
        TestGroupCall.cluster.fake_shell.add(results, "run", ['command3'], usage_limit=1)

        node.wait_commands_successful(['command1', 'command2', 'command3'], sudo=False, timeout=0)

        for cmd, expected_calls in (('command1', 1), ('command2', 2), ('command3', 1)):
            actual_calls = TestGroupCall.cluster.fake_shell.called_times(node.get_host(), 'run', [cmd])
            self.assertEqual(expected_calls, actual_calls, "Number of calls is not expected")


if __name__ == '__main__':
    unittest.main()
