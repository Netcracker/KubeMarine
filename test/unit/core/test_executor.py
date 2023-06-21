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

from concurrent.futures import TimeoutError

from invoke import UnexpectedExit

from kubemarine import demo
from kubemarine.core.executor import RunnersResult
from kubemarine.core.group import GroupException


class RemoteExecutorTest(unittest.TestCase):
    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_get_merged_results_all_success(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("echo \"foo\"")
            exe.flush()

            for result in exe.get_merged_runners_result().values():
                self.assertEqual("foo\n", result.stdout)

    def test_flush_all_fail(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("false")
            exception = None
            try:
                exe.flush()
            except GroupException as exc:
                exception = exc
            for result in exception.result.values():
                self.assertIsInstance(result, UnexpectedExit)

    def test_get_merged_results_all_exited_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("false", warn=True)
            exe.flush()

            for result in exe.get_merged_runners_result().values():
                self.assertIsInstance(result, RunnersResult)
                self.assertEqual(1, result.exited)

    def test_flush_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("sleep 1000", warn=True)
            exception = None
            try:
                exe.flush()
            except GroupException as exc:
                exception = exc
            for result in exception.result.values():
                self.assertIsInstance(result, TimeoutError)

    def test_get_merged_results_multiple_commands(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("echo \"foo\"")
            exe.group.run("echo \"bar\"")

            exe.flush()

            for result in exe.get_merged_runners_result().values():
                self.assertEqual("foo\nbar\n", result.stdout)

    def test_get_merged_results_filter_last_command_result(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        tokens = []
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("echo \"foo\"")
            tokens.append(exe.group.run("echo \"bar\""))

            exe.flush()

            for result in exe.get_merged_runners_result(tokens).values():
                self.assertEqual("bar\n", result.stdout)

    def test_flush_first_command_excepted_result_excepted(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("false")
            exe.group.run("echo \"bar\"")
            exe.group.put(io.StringIO('test'), '/fake/path')

            exception = None
            try:
                exe.flush()
            except GroupException as exc:
                exception = exc

            self.assertIsNotNone(exception, "Exception was not raised")
            for result in exception.result.values():
                self.assertIsInstance(result, UnexpectedExit)

            for host in self.cluster.nodes['all'].get_hosts():
                self.assertIsNone(self.cluster.fake_fs.read(host, '/fake/path'))

    def test_not_throw_on_failed_all_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.run("false", warn=True)

        for result in exe.get_merged_runners_result().values():
            self.assertIsInstance(result, RunnersResult)
            self.assertEqual(1, result.exited)

    def test_throw_on_failed_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with self.assertRaises(GroupException), \
                self.cluster.nodes["all"].executor() as exe:
            exe.group.run("sleep 1000", warn=True)

    def test_write_large_stream(self):
        self.cluster.fake_fs.emulate_latency = True
        with self.cluster.nodes["all"].executor() as exe:
            exe.group.put(io.StringIO('a' * 100000), '/fake/path')

        for host in self.cluster.nodes["all"].get_hosts():
            self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))

    def test_write_large_file(self):
        self.cluster.fake_fs.emulate_latency = True
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, 'file.txt')
            with open(file, 'w') as f:
                f.write('a' * 100000)

            with self.cluster.nodes["all"].executor() as exe:
                exe.group.put(file, '/fake/path')

            for host in self.cluster.nodes["all"].get_hosts():
                self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))


if __name__ == '__main__':
    unittest.main()
