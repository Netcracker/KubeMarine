#!/usr/bin/env python3

import unittest

from kubetool import demo


class KubernetesClusterTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    def test_make_group_from_strs(self):
        # TODO:
        pass

    def test_make_group_from_nodegroups(self):
        # TODO:
        pass

    def test_make_group_from_connections(self):
        # TODO:
        pass
