#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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
import random

import fabric

from kubemarine import demo
from kubemarine.demo import FakeKubernetesCluster


class TestGroupCreation(unittest.TestCase):

    # Test should from the following cluster:
    # master-1 roles: [master, worker]
    # worker-1 roles: [worker]
    # Get only node with single worker role using filter lambda function
    def test_new_group_from_lambda_filter(self):
        multirole_inventory = demo.generate_inventory(balancer=0, master=1, worker=['master-1', 'worker-1'])
        cluster = demo.new_cluster(multirole_inventory)

        expected_group = cluster.make_group(list(cluster.nodes['worker'].nodes.keys())[1:])
        filtered_group = cluster.nodes['worker'].new_group(apply_filter=lambda node: 'master' not in node['roles'])

        self.assertDictEqual(expected_group.nodes, filtered_group.nodes, msg="Filtered groups do not match")

    def test_exclude_group(self):
        inventory = demo.generate_inventory(balancer=2, master=2, worker=0)
        cluster = demo.new_cluster(inventory)

        result_group = cluster.nodes['all'].exclude_group(cluster.nodes['balancer'])

        self.assertDictEqual(cluster.nodes['master'].nodes, result_group.nodes, msg="Final groups do not match")

    def test_exclude_group_2(self):
        multirole_inventory = demo.generate_inventory(balancer=0, master=1, worker=['master-1', 'worker-1'])
        cluster = demo.new_cluster(multirole_inventory)

        expected_group = cluster.make_group(list(cluster.nodes['worker'].nodes.keys())[1:])
        result_group = cluster.nodes['worker'].exclude_group(cluster.nodes['master'])

        self.assertDictEqual(expected_group.nodes, result_group.nodes, msg="Final groups do not match")

    def test_include_group(self):
        inventory = demo.generate_inventory(balancer=2, master=2, worker=0)
        cluster = demo.new_cluster(inventory)

        result_group = cluster.nodes['balancer'].include_group(cluster.nodes['master'])

        self.assertDictEqual(cluster.nodes['all'].nodes, result_group.nodes, msg="Final groups do not match")


class TestGroupCall(unittest.TestCase):
    cluster: FakeKubernetesCluster = None

    @classmethod
    def setUpClass(cls):
        cls.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def tearDown(self):
        TestGroupCall.cluster.fake_shell.reset()

    def test_run_empty_group(self):
        # bug reproduces inside _do(), that is why it is necessary to use real cluster
        cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA), fake=False)
        empty_group = cluster.nodes["worker"].new_group(apply_filter=lambda node: 'xxx' in node['roles'])
        # if there no nodes in empty group - an exception should not be produced - empty result should be returned
        empty_group.run('whoami', is_async=True)
        empty_group.run('whoami', is_async=False)

    def test_GroupException_one_node_failed(self):
        all_nodes = TestGroupCall.cluster.nodes["all"]
        results = demo.create_nodegroup_result(all_nodes, stdout='example result')
        results[random.choice(list(all_nodes.nodes.keys()))] = Exception('Some error')

        TestGroupCall.cluster.fake_shell.add(results, "run", ['some command'])

        exception = None
        try:
            all_nodes.run('some command')
        except fabric.group.GroupException as e:
            exception = e

        self.assertIsNotNone(exception, msg="GroupException should be raised")
        nested_exc = 0
        for _, result in exception.result.items():
            if isinstance(result, Exception):
                nested_exc += 1
                self.assertEqual('Some error', result.args[0], msg="Unexpected exception message")

        self.assertEqual(1, nested_exc, msg="One wrapped exception should happen")


if __name__ == '__main__':
    unittest.main()
