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

import fabric
from concurrent.futures import TimeoutError

from fabric.exceptions import GroupException
from invoke import UnexpectedExit

from kubemarine import demo
from kubemarine.core.executor import RemoteExecutor
from test.unit import EnvSetup


class RemoteExecutorTest(EnvSetup):
    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_get_merged_results_all_success(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("echo \"foo\"")
            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results().items():
                self.assertEqual("foo\n", result.stdout)

    def test_get_merged_results_all_fail(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("false")
            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results().items():
                self.assertIsInstance(result, UnexpectedExit)

    def test_get_merged_results_all_exited_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("false", warn=True)
            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results().items():
                self.assertIsInstance(result, fabric.runners.Result)
                self.assertEqual(1, result.exited)

    def test_get_merged_results_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("sleep 1000", warn=True)
            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results().items():
                self.assertIsInstance(result, TimeoutError)

    def test_get_merged_results_multiple_commands(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        with RemoteExecutor(self.cluster) as exe:
            for host in self.cluster.nodes["all"].get_hosts():
                node = self.cluster.make_group([host])
                node.run("echo \"foo\"")
                node.run("echo \"bar\"")

            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results().items():
                self.assertEqual("foo\nbar\n", result.stdout)

    def test_get_merged_results_filter_last_command_result(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        tokens = []
        with RemoteExecutor(self.cluster) as exe:
            for host in self.cluster.nodes["all"].get_hosts():
                node = self.cluster.make_group([host])
                node.run("echo \"foo\"")
                tokens.append(node.run("echo \"bar\""))

            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results(tokens).items():
                self.assertEqual("bar\n", result.stdout)

    def test_get_merged_results_filter_last_command_result_first_excepted(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        tokens = []
        with RemoteExecutor(self.cluster) as exe:
            for host in self.cluster.nodes["all"].get_hosts():
                node = self.cluster.make_group([host])
                node.run("false")
                tokens.append(node.run("echo \"bar\""))

            exe.flush()

            for cxn, result in exe.get_merged_nodegroup_results(tokens).items():
                self.assertIsInstance(result, UnexpectedExit)

    def test_not_throw_on_failed_all_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("false", warn=True)

        for cxn, result in exe.get_merged_nodegroup_results().items():
            self.assertIsInstance(result, fabric.runners.Result)
            self.assertEqual(1, result.exited)

        # does not fail
        exe.get_merged_result()

    def test_throw_on_failed_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with self.assertRaises(GroupException), \
                RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("sleep 1000", warn=True)

    def test_get_merged_result_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with RemoteExecutor(self.cluster) as exe:
            self.cluster.nodes["all"].run("sleep 1000", warn=True)
            exe.flush()
            with self.assertRaises(GroupException):
                exe.get_merged_result()


if __name__ == '__main__':
    unittest.main()
