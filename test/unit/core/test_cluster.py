#!/usr/bin/env python3

import unittest

from kubetool import demo


class KubernetesClusterTest(unittest.TestCase):

    # TODO: add more tests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_make_group_from_strs(self):
        expected_group = self.cluster.nodes['master']
        actual_group = self.cluster.make_group(['10.101.1.2', '10.101.1.3', '10.101.1.4'])
        self.assertEqual(expected_group, actual_group, msg="Created group is not equivalent to master group")

    def test_make_group_from_nodegroups(self):
        masters = self.cluster.nodes['master']
        balancer = self.cluster.nodes['balancer']
        expected_group = balancer.include_group(masters)
        actual_group = self.cluster.make_group([balancer, masters])
        self.assertEqual(expected_group, actual_group, msg="Created group is not equivalent to merged group")

    def test_make_group_from_connections(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        expected_group = self.cluster.nodes['master']
        actual_group = self.cluster.make_group([
            all_nodes_group['10.101.1.2'],
            all_nodes_group['10.101.1.3'],
            all_nodes_group['10.101.1.4']
        ])
        self.assertEqual(expected_group, actual_group, msg="Created group is not equivalent to all masters group")

    def test_make_group_from_any_types(self):
        all_nodes_group = self.cluster.nodes['all'].nodes
        actual_group = self.cluster.make_group([
            all_nodes_group['10.101.1.1'],
            self.cluster.nodes['master'],
            '10.101.1.5',
            '10.101.1.6',
            '10.101.1.7'
        ])
        self.assertEqual(self.cluster.nodes['all'], actual_group,
                         msg="Created group is not equivalent to all nodes group")
