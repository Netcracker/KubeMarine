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

from kubemarine import demo
from kubemarine.core.executor import RunnersResult, UnexpectedExit
from kubemarine.core.group import GroupException, RemoteGroupException, CollectorCallback


class RemoteExecutorTest(unittest.TestCase):
    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_get_merged_results_all_success(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        collector = CollectorCallback(self.cluster)
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("echo \"foo\"", callback=collector)
            exe.flush()

            for result in collector.result.values():
                self.assertEqual("foo\n", result.stdout)

    def test_flush_all_fail(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("false")
            exception = None
            try:
                exe.flush()
            except RemoteGroupException as exc:
                exception = exc
            for results_list in exception.results.values():
                self.assertIsInstance(results_list[0], UnexpectedExit)

    def test_get_merged_results_all_exited_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        collector = CollectorCallback(self.cluster)
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("false", warn=True, callback=collector)
            exe.flush()

            for result in collector.result.values():
                self.assertIsInstance(result, RunnersResult)
                self.assertEqual(1, result.exited)

    def test_flush_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("sleep 1000", warn=True)
            exception = None
            try:
                exe.flush()
            except RemoteGroupException as exc:
                exception = exc
            for results_list in exception.results.values():
                self.assertIsInstance(results_list[0], TimeoutError)

    def test_get_merged_results_multiple_commands(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        collector = CollectorCallback(self.cluster)
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("echo \"foo\"", callback=collector)
            exe.group.run("echo \"bar\"", callback=collector)

            exe.flush()

            for result in collector.result.values():
                self.assertEqual("foo\nbar\n", result.stdout)

    def test_get_merged_results_filter_last_command_result(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        collector = CollectorCallback(self.cluster)
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("echo \"foo\"")
            exe.group.run("echo \"bar\"", callback=collector)

            exe.flush()

            for result in collector.result.values():
                self.assertEqual("bar\n", result.stdout)

    def test_flush_first_command_failed_result_excepted(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("false")
            exe.group.run("echo \"bar\"")
            exe.group.put(io.StringIO('test'), '/fake/path')

            exception = None
            try:
                exe.flush()
            except RemoteGroupException as exc:
                exception = exc

            self.assertIsNotNone(exception, "Exception was not raised")
            for results_list in exception.results.values():
                self.assertIsInstance(results_list[0], UnexpectedExit)

            for host in self.cluster.nodes['all'].get_hosts():
                self.assertIsNone(self.cluster.fake_fs.read(host, '/fake/path'))

    def test_second_command_failed_first_collected(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], stdout="bar\n", code=1)
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\" && false"])
        with self.cluster.nodes["all"].new_executor() as exe:
            first_token = exe.group.run("echo \"foo\"")
            exe.group.run("echo \"bar\" && false")

            exception = None
            try:
                exe.flush()
            except RemoteGroupException as exc:
                exception = exc

            self.assertIsNotNone(exception, "Exception was not raised")
            self.assertEqual(exe.group.nodes, set(exception.results), "Exception results were not collected")
            for results_list in exception.results.values():
                self.assertEqual(2, len(results_list), "Two commands should be run")
                result = results_list[1]
                self.assertIsInstance(result, UnexpectedExit)
                self.assertEqual("echo \"bar\" && false", result.result.command,
                                 "Unexpected exit should contain original command string of only failed command")
                self.assertEqual("bar\n", result.result.stdout,
                                 "Unexpected exit should contain stdout of only failed command")

            last_results = exe.get_last_results()
            self.assertEqual(exe.group.nodes, set(last_results), "Last results were not collected")
            for tokenized_results in last_results.values():
                result = tokenized_results.get(first_token)
                self.assertIsNotNone(result, "Result of the first command was not collected")
                self.assertEqual("echo \"foo\"", result.command,
                                 "Unexpected command string of the first successful command")
                self.assertEqual("foo\n", result.stdout,
                                 "Unexpected result of the first successful command")

    def test_not_throw_on_failed_all_warn(self):
        results = demo.create_nodegroup_result(self.cluster.nodes["all"], code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("false", warn=True)

    def test_throw_on_failed_all_excepted(self):
        results = demo.create_exception_result(self.cluster.nodes["all"], TimeoutError())
        self.cluster.fake_shell.add(results, "run", ["sleep 1000"])
        with self.assertRaises(GroupException), \
                self.cluster.nodes["all"].new_executor() as exe:
            exe.group.run("sleep 1000", warn=True)

    def test_execute_without_context(self):
        group = self.cluster.nodes["all"].new_defer()
        results = demo.create_nodegroup_result(group, stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])

        collector = CollectorCallback(self.cluster)
        group.run("echo \"foo\"", callback=collector)
        group.flush()
        for result in collector.result.values():
            self.assertEqual("foo\n", result.stdout)

    def test_execute_members_without_context(self):
        group = self.cluster.nodes["all"].new_defer()
        results = demo.create_nodegroup_result(group, stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])

        collector = CollectorCallback(self.cluster)
        for node in group.get_ordered_members_list():
            node.run("echo \"foo\"", callback=collector)

        group.flush()
        self.assertEqual(group.nodes_amount(), len(collector.result))
        for result in collector.result.values():
            self.assertEqual("foo\n", result.stdout)

    def test_collect_results_with_callback(self):
        group = self.cluster.nodes["all"].new_defer()
        results = demo.create_hosts_result(group.get_hosts(), stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        for i, host in enumerate(group.get_hosts()):
            result = demo.create_result(stdout=f"bar{i}\n")
            self.cluster.fake_shell.add({host: result}, "run", [f"echo \"bar{i}\""])

        callback = CollectorCallback(self.cluster)
        group.run("echo \"foo\"", callback=callback)
        for i, node in enumerate(group.get_ordered_members_list()):
            node.run(f"echo \"bar{i}\"", callback=callback)

        group.flush()
        for i, host in enumerate(group.get_hosts()):
            result = callback.results.get(host, [])
            self.assertEqual(2, len(result), "Result was not collected")
            self.assertEqual("foo\n", result[0].stdout, "Result was not collected")
            self.assertEqual(f"bar{i}\n", result[1].stdout, "Result was not collected")

    def test_command_failed_result_not_collected_with_callback(self):
        group = self.cluster.nodes["all"].new_defer()
        results = demo.create_hosts_result(group.get_hosts(), stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_hosts_result(group.get_hosts(), code=1)
        self.cluster.fake_shell.add(results, "run", ["false"])

        callback = CollectorCallback(self.cluster)
        group.run("echo \"foo\"", callback=callback)
        group.run("false", callback=callback)
        with self.assertRaises(GroupException):
            group.flush()

        for i, host in enumerate(group.get_hosts()):
            result = callback.results.get(host, [])
            self.assertEqual(1, len(result), "Result should be partially collected")
            self.assertEqual("foo\n", result[0].stdout, "Result was not collected")

    def test_represent_group_exception_one_command_failed(self):
        group = self.cluster.nodes["control-plane"].new_defer()
        results = demo.create_hosts_result(group.get_hosts(), stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_hosts_result(group.get_hosts(), stdout="bar\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\""])
        results = demo.create_hosts_result(group.get_hosts(), stderr="failed\n", code=1)
        self.cluster.fake_shell.add(results, "run", ["echo \"failed\" 2>&1 && false"])

        group.run("echo \"foo\"")
        group.run("echo \"bar\"")
        group.get_first_member().run("echo \"failed\" 2>&1 && false")
        group.get_ordered_members_list()[2].put(io.StringIO('test'), '/fake/path')

        exception = None
        try:
            group.flush()
        except RemoteGroupException as exc:
            exception = exc

        self.assertIsNotNone(exception, "Exception was not raised")
        expected_results_str = ("""\
            10.101.1.2: code=0
            \t=== stdout ===
            \tfoo
            \tbar
            \t
            \tEncountered a bad command exit code!
            \t
            \tCommand: 'echo "failed" 2>&1 && false'
            \t
            \tExit code: 1
            \t
            \t=== stderr ===
            \tfailed
            \t
            10.101.1.3: code=0
            \t=== stdout ===
            \tfoo
            \tbar
            \t
            10.101.1.4: code=0
            \t=== stdout ===
            \tfoo
            \tbar
            \t"""
                                ).replace("""\
            """, ""
                                          )
        self.assertEqual(expected_results_str, str(exception),
                         "Unexpected textual representation of remote group exception")

    def test_represent_group_exception_timeout(self):
        group = self.cluster.nodes["control-plane"].new_defer()
        results = demo.create_hosts_result(group.get_hosts(), stdout="foo\n")
        self.cluster.fake_shell.add(results, "run", ["echo \"foo\""])
        results = demo.create_hosts_result(group.get_hosts(), stdout="bar\n")
        results[group.get_first_member().get_host()] = demo.create_result(stdout="bar\n", timeout=10)
        self.cluster.fake_shell.add(results, "run", ["echo \"bar\" && sleep 10"])

        group.run("echo \"foo\"", timeout=10)
        group.run("echo \"bar\" && sleep 10", timeout=10)

        exception = None
        try:
            group.flush()
        except RemoteGroupException as exc:
            exception = exc

        self.assertIsNotNone(exception, "Exception was not raised")
        expected_results_str = ("""\
            10.101.1.2: code=0
            \t=== stdout ===
            \tfoo
            \t
            \tCommand did not complete within 10 seconds!
            \t
            \tCommand: 'echo "bar" && sleep 10'
            \t
            \t=== stdout ===
            \tbar
            \t
            10.101.1.3: code=0
            \t=== stdout ===
            \tfoo
            \tbar
            \t
            10.101.1.4: code=0
            \t=== stdout ===
            \tfoo
            \tbar
            \t"""
                                ).replace("""\
            """, ""
                                          )
        self.assertEqual(expected_results_str, str(exception),
                         "Unexpected textual representation of remote group exception")

    def test_write_large_stream(self):
        self.cluster.fake_fs.emulate_latency = True
        with self.cluster.nodes["all"].new_executor() as exe:
            exe.group.put(io.StringIO('a' * 100000), '/fake/path')

        for host in self.cluster.nodes["all"].get_hosts():
            self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))

    def test_write_large_file(self):
        self.cluster.fake_fs.emulate_latency = True
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, 'file.txt')
            with open(file, 'w') as f:
                f.write('a' * 100000)

            with self.cluster.nodes["all"].new_executor() as exe:
                exe.group.put(file, '/fake/path')

            for host in self.cluster.nodes["all"].get_hosts():
                self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))


if __name__ == '__main__':
    unittest.main()
