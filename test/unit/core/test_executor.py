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

from typing import Union, List

import fabric
import invoke

from kubemarine import demo
from kubemarine.core.executor import RunnersResult, UnexpectedExit, GenericResult, CommandTimedOut
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

        for host in group.get_hosts():
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
            with open(file, 'w', encoding='utf-8') as f:
                f.write('a' * 100000)

            with self.cluster.nodes["all"].new_executor() as exe:
                exe.group.put(file, '/fake/path')

            for host in self.cluster.nodes["all"].get_hosts():
                self.assertEqual('a' * 100000, self.cluster.fake_fs.read(host, '/fake/path'))


class ReparseFabricResultTest(unittest.TestCase):
    # pylint: disable=protected-access

    @classmethod
    def setUpClass(cls):
        cls.cluster = cluster = demo.new_cluster(demo.generate_inventory(**demo.ALLINONE))
        node = cluster.nodes['all']
        cls.host = node.get_host()
        cls.executor = executor = node.new_executor()
        cls.sep = executor._command_separator

    def tearDown(self):
        self.executor._connections_queue = {}

    def _get_patch(self):
        return self.executor._get_callables()[0]

    def _reparse_results(self, result: Union[invoke.UnexpectedExit, invoke.CommandTimedOut, fabric.runners.Result]) \
            -> List[GenericResult]:
        batch = self._get_patch()
        reparsed_result = self.executor._reparse_results({self.host: result}, batch)
        return list(reparsed_result[self.host].values())

    def _create_result(self, stdout: str = '', stderr: str = '',
                       code: int = 0) -> fabric.runners.Result:
        batch = self._get_patch()
        _, args, _ = self.executor._prepare_merged_action(self.host, batch[self.host])
        result = fabric.runners.Result(stdout=stdout, stderr=stderr, exited=code,
                                       connection=self.cluster.connection_pool.get_connection(self.host),
                                       command=args[0])
        return result

    def _queue(self, num: int, warn=False):
        for i in range(num):
            self.executor.queue([self.host], ('run', (f'fake command {i}',), {'warn': warn}))

    def test_reparse_single_command(self):
        self._queue(1)
        result = self._create_result(stdout='test\n', code=0)
        reparsed_result = self._reparse_results(result)
        self.assertEqual(1, len(reparsed_result))
        self.assertEqual('test\n', reparsed_result[0].stdout)
        self.assertEqual(0, reparsed_result[0].exited)
        self.assertEqual('fake command 0', reparsed_result[0].command)

    def test_reparse_single_command_empty(self):
        self._queue(1)
        result = self._create_result(stdout='', code=13)
        reparsed_result = self._reparse_results(result)
        self.assertEqual(1, len(reparsed_result))
        self.assertEqual('', reparsed_result[0].stdout)
        self.assertEqual(13, reparsed_result[0].exited)
        self.assertEqual('fake command 0', reparsed_result[0].command)

    def test_reparse_few_commands_warn(self):
        self._queue(3, warn=True)
        result = self._create_result(stdout=f'out0\n{self.sep}\n0\n{self.sep}\n'
                                            f'out1\n{self.sep}\n13\n{self.sep}\n'
                                            f'out2\n',
                                     stderr=f'err0\n{self.sep}\n'
                                            f'err1\n{self.sep}\n'
                                            f'err2\n',
                                     code=1)
        reparsed_result = self._reparse_results(result)
        self.assertEqual(3, len(reparsed_result))
        for i in range(3):
            self.assertEqual(f'out{i}\n', reparsed_result[i].stdout)
            self.assertEqual(f'err{i}\n', reparsed_result[i].stderr)
            expected_exited = 0 if i == 0 else 13 if i == 1 else 1
            self.assertEqual(expected_exited, reparsed_result[i].exited)
            self.assertEqual(f'fake command {i}', reparsed_result[i].command)

    def test_reparse_few_commands_unexpected_exit(self):
        self._queue(3)
        result = self._create_result(stdout=f'out0\n{self.sep}\n0\n{self.sep}\n'
                                            f'out1\n{self.sep}\n0\n{self.sep}\n'
                                            f'out2\n',
                                     stderr=f'err0\n{self.sep}\n'
                                            f'err1\n{self.sep}\n'
                                            f'err2\n',
                                     code=1)
        result = invoke.UnexpectedExit(result)
        reparsed_results = self._reparse_results(result)
        self.assertEqual(3, len(reparsed_results))
        for i in range(3):
            reparsed_result = reparsed_results[i]
            if i == 2:
                self.assertIsInstance(reparsed_result, UnexpectedExit)
                reparsed_result = reparsed_result.result

            self.assertIsInstance(reparsed_result, RunnersResult)
            self.assertEqual(f'out{i}\n', reparsed_result.stdout)
            self.assertEqual(f'err{i}\n', reparsed_result.stderr)
            self.assertEqual(1 if i == 2 else 0, reparsed_result.exited)
            self.assertEqual(f'fake command {i}', reparsed_result.command)

    def test_reparse_few_commands_timeout_last(self):
        self._queue(3)
        result = self._create_result(stdout=f'out0{self.sep}\n0\n{self.sep}\n'
                                            f'{self.sep}\n0\n{self.sep}\n'
                                            f'out2\n',
                                     stderr=f'err0\n{self.sep}\n'
                                            f'{self.sep}\n'
                                            f'err2',
                                     code=-1)
        result = invoke.CommandTimedOut(result, 10)
        reparsed_results = self._reparse_results(result)
        self.assertEqual(3, len(reparsed_results))
        for i in range(3):
            reparsed_result = reparsed_results[i]
            if i == 2:
                self.assertIsInstance(reparsed_result, CommandTimedOut)
                reparsed_result = reparsed_result.result

            self.assertIsInstance(reparsed_result, RunnersResult)
            expected_out = 'out0' if i == 0 else '' if i == 1 else 'out2\n'
            self.assertEqual(expected_out, reparsed_result.stdout)
            expected_err = 'err0\n' if i == 0 else '' if i == 1 else 'err2'
            self.assertEqual(expected_err, reparsed_result.stderr)
            self.assertEqual(-1 if i == 2 else 0, reparsed_result.exited)
            self.assertEqual(f'fake command {i}', reparsed_result.command)

    def test_reparse_few_commands_timeout_intermediate(self):
        # emulate partial separator
        for i, second_out in enumerate((
                '',
                'out1',
                'out1\n'
        )):
            with self.subTest(i):
                self._queue(3)
                result = self._create_result(stdout=f'out0\n{self.sep}\n0\n{self.sep}\n' + second_out,
                                             stderr=f'err0\n{self.sep}\n',
                                             code=-1)
                result = invoke.CommandTimedOut(result, 10)
                reparsed_results = self._reparse_results(result)
                self.assertEqual(2, len(reparsed_results))

                reparsed_result = reparsed_results[0]
                self.assertIsInstance(reparsed_result, RunnersResult)
                self.assertEqual(f'out0\n', reparsed_result.stdout)
                self.assertEqual(f'err0\n', reparsed_result.stderr)
                self.assertEqual(0, reparsed_result.exited)
                self.assertEqual('fake command 0', reparsed_result.command)

                reparsed_result = reparsed_results[1]
                self.assertIsInstance(reparsed_result, CommandTimedOut)
                self.assertEqual(second_out, reparsed_result.result.stdout)
                self.assertEqual('', reparsed_result.result.stderr)
                self.assertEqual(-1, reparsed_result.result.exited)
                self.assertEqual('fake command 1', reparsed_result.result.command)

                self.tearDown()

    def test_reparse_few_commands_timeout_intermediate_partial_separator1(self):
        self._queue(3)
        # emulate partial separator
        result = self._create_result(stdout=f'out0\n{self.sep}\n0\n{self.sep}\n'
                                            f'out1\n{self.sep[:5]}',
                                     stderr=f'err0\n{self.sep}\n'
                                            f'err1\n{self.sep[:5]}',
                                     code=-1)
        result = invoke.CommandTimedOut(result, 10)
        reparsed_results = self._reparse_results(result)
        self.assertEqual(2, len(reparsed_results))

        reparsed_result = reparsed_results[0]
        self.assertIsInstance(reparsed_result, RunnersResult)
        self.assertEqual(f'out0\n', reparsed_result.stdout)
        self.assertEqual(f'err0\n', reparsed_result.stderr)
        self.assertEqual(0, reparsed_result.exited)
        self.assertEqual('fake command 0', reparsed_result.command)

        reparsed_result = reparsed_results[1]
        self.assertIsInstance(reparsed_result, CommandTimedOut)
        self.assertEqual(f'out1\n{self.sep[:5]}', reparsed_result.result.stdout)
        self.assertEqual(f'err1\n{self.sep[:5]}', reparsed_result.result.stderr)
        self.assertEqual(-1, reparsed_result.result.exited)
        self.assertEqual('fake command 1', reparsed_result.result.command)

    def test_reparse_few_commands_timeout_intermediate_partial_separator2(self):
        # emulate partial separator
        for i, out in enumerate((
                f'out0{self.sep}',
                f'out0{self.sep}\n',
                f'out0\n{self.sep}',
                f'out0\n{self.sep}\n',
                f'out0\n{self.sep}\n1',
        )):
            with self.subTest(i):
                self._queue(3)
                result = self._create_result(stdout=out,
                                             stderr=f'err0{self.sep}',
                                             code=-1)
                result = invoke.CommandTimedOut(result, 10)
                reparsed_results = self._reparse_results(result)
                self.assertEqual(1, len(reparsed_results))

                reparsed_result = reparsed_results[0]
                self.assertIsInstance(reparsed_result, CommandTimedOut)
                self.assertEqual('out0' if i < 2 else 'out0\n', reparsed_result.result.stdout)
                self.assertEqual('err0', reparsed_result.result.stderr)
                self.assertEqual(-1, reparsed_result.result.exited)
                self.assertEqual('fake command 0', reparsed_result.result.command)

                self.tearDown()

    def test_reparse_few_commands_timeout_intermediate_partial_separator3(self):
        # emulate partial separator
        for i, out in enumerate((
                f'out0\n{self.sep}\n13\n',
                f'out0\n{self.sep}\n13\n{self.sep[:5]}',
                f'out0\n{self.sep}\n13\n{self.sep}',
                f'out0\n{self.sep}\n13\n{self.sep}\n',
                f'out0\n{self.sep}\n13\n{self.sep}\nout1',
        )):
            with self.subTest(i):
                self._queue(3)
                result = self._create_result(stdout=out,
                                             stderr=f'err0{self.sep}',
                                             code=-1)
                result = invoke.CommandTimedOut(result, 10)
                reparsed_results = self._reparse_results(result)
                self.assertEqual(2, len(reparsed_results))

                reparsed_result = reparsed_results[0]
                self.assertIsInstance(reparsed_result, RunnersResult)
                self.assertEqual(f'out0\n', reparsed_result.stdout)
                self.assertEqual(f'err0', reparsed_result.stderr)
                self.assertEqual(13, reparsed_result.exited)
                self.assertEqual('fake command 0', reparsed_result.command)

                reparsed_result = reparsed_results[1]
                self.assertIsInstance(reparsed_result, CommandTimedOut)
                expected_out = 'out1' if i == 4 else ''
                self.assertEqual(expected_out, reparsed_result.result.stdout)
                self.assertEqual('', reparsed_result.result.stderr)
                self.assertEqual(-1, reparsed_result.result.exited)
                self.assertEqual('fake command 1', reparsed_result.result.command)

                self.tearDown()

    def test_reparse_few_commands_timeout_intermediate_partial_separator4(self):
        self._queue(3)
        # emulate partial separator
        result = self._create_result(stdout=f'out0\n{self.sep}\n255\n{self.sep}\n',
                                     stderr=f'err0{self.sep[:5]}',
                                     code=-1)
        result = invoke.CommandTimedOut(result, 10)
        reparsed_results = self._reparse_results(result)
        self.assertEqual(1, len(reparsed_results))

        reparsed_result = reparsed_results[0]
        self.assertIsInstance(reparsed_result, CommandTimedOut)
        self.assertEqual(f'out0\n', reparsed_result.result.stdout)
        self.assertEqual(f'err0{self.sep[:5]}', reparsed_result.result.stderr)
        self.assertEqual(255, reparsed_result.result.exited)
        self.assertEqual('fake command 0', reparsed_result.result.command)


if __name__ == '__main__':
    unittest.main()
