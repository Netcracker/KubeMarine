import unittest

import fabric
from concurrent.futures import TimeoutError

from fabric.exceptions import GroupException
from invoke import UnexpectedExit

from kubemarine import demo
from kubemarine.core.executor import RemoteExecutor


class RemoteExecutorTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
