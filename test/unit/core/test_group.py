#!/usr/bin/env python3

import unittest

import fabric

from kubetool.core.group import NodeGroup, NodeGroupResult
from kubetool import demo


class NodeGroupResultsTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_nodegroup_result_to_str(self):
        expected_results_str = '''	10.101.1.2: code=1
		STDERR: sudo: kubectl: command not found
	10.101.1.3: code=1
		STDERR: sudo: kubectl: command not found
	10.101.1.4: code=1
		STDERR: sudo: kubectl: command not found'''
        results: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['master'], code=1,
                                                                stderr='sudo: kubectl: command not found')
        actual_results_str = str(results)
        self.assertEqual(expected_results_str, actual_results_str, msg="NodeGroupResult string generated with invalid "
                                                                       "formatting")

    def test_get_simple_out(self):
        results: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['balancer'], code=0,
                                                                stdout='example text message')
        self.assertEqual('example text message', results.get_simple_out(), msg="Simple out getter method does not "
                                                                               "return a string with the correct value")

    def test_equals_nodegroup_results(self):
        results1: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0,
                                                                 stdout='example text message')
        results2: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0,
                                                                 stdout='example text message')
        self.assertEqual(results1, results2, msg="Identical nodegroup results are not equal")

    def test_not_equals_nodegroup_results(self):
        results1: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0,
                                                                 stdout='example text message')
        results2: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0,
                                                                 stdout='foo bar')
        self.assertNotEqual(results1, results2, msg="Different nodegroup results are equal")

    def test_get_nodegroup_from_results(self):
        # Manually create new group object to verify with existing masters group
        masters_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3', '10.101.1.4'])
        results: NodeGroupResult = demo.create_nodegroup_result(masters_group, code=0, stdout='foo bar')
        group_from_results: NodeGroup = results.get_group()
        self.assertEqual(masters_group, group_from_results, msg="Group from nodegroup is not the same as manual group")

    def test_any_failed_via_bad_code(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': fabric.runners.Result(stderr='error', exited=1, connection=all_nodes_group['10.101.1.2']),
            '10.101.1.3': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        self.assertTrue(results.is_any_failed(), msg="Failed to identify at least one failed node")

    def test_any_failed_via_exception(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        print(results)
        self.assertTrue(results.is_any_failed(), msg="Failed to identify at least one failed node")
        pass

    def test_nobody_failed(self):
        results = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0, stdout='foo bar')
        self.assertFalse(results.is_any_failed(), msg="Non-failed node was identified as failed")

    def test_get_exited_nodes_list(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_exited_nodes_list = [
            all_nodes_group['10.101.1.1'],
            all_nodes_group['10.101.1.3']
        ]
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_nodes_list = results.get_exited_nodes_list()
        self.assertEqual(expected_exited_nodes_list, actual_nodes_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_exited_nodes_group(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_exited_group = self.cluster.make_group(['10.101.1.1', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_group = results.get_exited_nodes_group()
        self.assertEqual(expected_exited_group, actual_group, msg="Actual group contains different nodes than expected")

    def test_get_excepted_nodes_list(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_excepted_nodes_list = [
            all_nodes_group['10.101.1.2'],
            all_nodes_group['10.101.1.3']
        ]
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': Exception('And there')
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_nodes_list = results.get_excepted_nodes_list()
        self.assertEqual(expected_excepted_nodes_list, actual_nodes_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_excepted_nodes_group(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_excepted_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': Exception('And there')
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_group = results.get_excepted_nodes_group()
        self.assertEqual(expected_excepted_group, actual_group, msg="Actual group contains different nodes than expected")

    def test_get_failed_nodes_list(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_failed_nodes_list = [
            all_nodes_group['10.101.1.2'],
            all_nodes_group['10.101.1.3']
        ]
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_nodes_list = results.get_failed_nodes_list()
        self.assertEqual(expected_failed_nodes_list, actual_nodes_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_failed_nodes_group(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_failed_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_group = results.get_failed_nodes_group()
        self.assertEqual(expected_failed_group, actual_group, msg="Actual group contains different nodes than expected")

    def test_get_nonzero_nodes_list(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_nonzero_nodes_list = [
            all_nodes_group['10.101.1.1'],
            all_nodes_group['10.101.1.3']
        ]
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.2']),
            '10.101.1.3': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_nodes_list = results.get_nonzero_nodes_list()
        self.assertEqual(expected_nonzero_nodes_list, actual_nodes_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_nonzero_nodes_group(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_nonzero_group = self.cluster.make_group(['10.101.1.1', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.1']),
            '10.101.1.2': fabric.runners.Result(stdout='ok', exited=0, connection=all_nodes_group['10.101.1.2']),
            '10.101.1.3': fabric.runners.Result(stdout='error', exited=1, connection=all_nodes_group['10.101.1.3'])
        }
        results = NodeGroupResult(self.cluster, host_to_result)
        actual_group = results.get_nonzero_nodes_group()
        self.assertEqual(expected_nonzero_group, actual_group, msg="Actual group contains different nodes than expected")
