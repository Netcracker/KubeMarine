#!/usr/bin/env python3

import unittest
from kubetool import demo, audit


class NodeGroupResultsTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cluster = demo.new_cluster(demo.generate_inventory(**demo.FULLHA))

    # TODO: test audit installation for debian
    # TODO: test audit configuring

    def test_audit_installation(self):
        pass

    def test_audit_configuring(self):
        pass
