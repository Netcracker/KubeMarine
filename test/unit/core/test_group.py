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


import unittest

from kubemarine.core.group import NodeGroup, NodeGroupResult, GroupResultException
from kubemarine import demo


class NodeGroupResultsTest(unittest.TestCase):

    def setUp(self):
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_nodegroup_result_to_str(self):
        expected_results_str = ("""\
            10.101.1.2: code=1
            \t=== stderr ===
            \tsudo: kubectl: command not found
            \t
            10.101.1.3: code=1
            \t=== stderr ===
            \tsudo: kubectl: command not found
            \t
            10.101.1.4: code=1
            \t=== stderr ===
            \tsudo: kubectl: command not found
            \t"""
                                ).replace("""\
            """, ""
                                          )
        results: NodeGroupResult = demo.create_nodegroup_result(self.cluster.nodes['control-plane'], code=1,
                                                                stderr='sudo: kubectl: command not found\n')
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
        # Manually create new group object to verify with existing control_planes group
        control_planes_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3', '10.101.1.4'])
        results: NodeGroupResult = demo.create_nodegroup_result(control_planes_group, code=0, stdout='foo bar')
        group_from_results: NodeGroup = results.get_group()
        self.assertEqual(control_planes_group.nodes, group_from_results.nodes,
                         msg="Group from nodegroup is not the same as manual group")

    def test_any_failed_via_bad_code(self):
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='ok', code=0),
            '10.101.1.2': demo.create_result(stderr='error', code=1),
            '10.101.1.3': demo.create_result(stdout='ok', code=0)
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        self.assertTrue(results.is_any_failed(), msg="Failed to identify at least one failed node")

    def test_nobody_failed(self):
        results = demo.create_nodegroup_result(self.cluster.nodes['all'], code=0, stdout='foo bar')
        self.assertFalse(results.is_any_failed(), msg="Non-failed node was identified as failed")

    def test_get_exited_nodes_list(self):
        expected_exited_hosts_list = [
            '10.101.1.1',
            '10.101.1.3'
        ]
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='ok', code=0),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': demo.create_result(stdout='ok', code=0)
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        exception = GroupResultException(results)
        actual_hosts_list = exception.get_exited_hosts_list()
        self.assertEqual(expected_exited_hosts_list, actual_hosts_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_exited_nodes_group(self):
        expected_exited_group = self.cluster.make_group(['10.101.1.1', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='ok', code=0),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': demo.create_result(stdout='error', code=1)
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        exception = GroupResultException(results)
        actual_group = exception.get_exited_nodes_group()
        self.assertEqual(expected_exited_group.nodes, actual_group.nodes,
                         msg="Actual group contains different nodes than expected")

    def test_get_excepted_nodes_list(self):
        expected_excepted_hosts_list = [
            '10.101.1.2',
            '10.101.1.3'
        ]
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='ok', code=0),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': Exception('And there')
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        exception = GroupResultException(results)
        actual_hosts_list = exception.get_excepted_hosts_list()
        self.assertEqual(expected_excepted_hosts_list, actual_hosts_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_excepted_nodes_group(self):
        expected_excepted_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='ok', code=0),
            '10.101.1.2': Exception('Something failed here'),
            '10.101.1.3': Exception('And there')
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        exception = GroupResultException(results)
        actual_group = exception.get_excepted_nodes_group()
        self.assertEqual(expected_excepted_group.nodes, actual_group.nodes,
                         msg="Actual group contains different nodes than expected")

    def test_get_failed_nodes_list(self):
        expected_nonzero_hosts_list = [
            '10.101.1.1',
            '10.101.1.3'
        ]
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='error', code=1),
            '10.101.1.2': demo.create_result(stdout='ok', code=0),
            '10.101.1.3': demo.create_result(stdout='error', code=1)
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        actual_hosts_list = results.get_failed_hosts_list()
        self.assertEqual(expected_nonzero_hosts_list, actual_hosts_list,
                         msg="Actual nodes list contains different nodes than expected")

    def test_get_failed_nodes_group(self):
        expected_nonzero_group = self.cluster.make_group(['10.101.1.1', '10.101.1.3'])
        host_to_result = {
            '10.101.1.1': demo.create_result(stdout='error', code=1),
            '10.101.1.2': demo.create_result(stdout='ok', code=0),
            '10.101.1.3': demo.create_result(stdout='error', code=1)
        }
        results = demo.create_nodegroup_result_by_hosts(self.cluster, host_to_result)
        actual_group = results.get_failed_nodes_group()
        self.assertEqual(expected_nonzero_group.nodes, actual_group.nodes,
                         msg="Actual group contains different nodes than expected")


if __name__ == '__main__':
    unittest.main()
