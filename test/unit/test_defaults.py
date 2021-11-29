#!/usr/bin/env python3

import unittest

from kubetool.core import defaults
from kubetool import demo


class DefaultsEnrichmentAppendControlPlain(unittest.TestCase):

    def test_controlplain_already_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'internal': '1.1.1.1',
            'external': '2.2.2.2'
        }
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '1.1.1.1')
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_already_internal_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'internal': '1.1.1.1'
        }
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '1.1.1.1')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_already_external_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'external': '2.2.2.2'
        }
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0])
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_calculated_half_vrrp_half_master(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0])
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_calculated_fully_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['vrrp_ips'][0] = {
            'ip': '192.168.0.1',
            'floating_ip': inventory['vrrp_ips'][0]
        }
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0]['ip'])
        self.assertEqual(inventory['control_plain']['external'], inventory['vrrp_ips'][0]['floating_ip'])

    def test_controlplain_calculated_half_fully_master(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], inventory['nodes'][0]['internal_address'])
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_control_endpoint_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
                'floating_ip': '1.1.1.1'
            },
            {
                'ip': '192.168.0.2',
                'floating_ip': '2.2.2.2',
                'control_endpoint': True
            }
        ]
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_control_half_endpoint_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
                'floating_ip': '1.1.1.1'
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], '1.1.1.1')

    def test_controlplain_control_half_endpoint_vrrp_half_master(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_control_half_endpoint_vrrp_half_endpoint_master(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        inventory['nodes'][1]['control_endpoint'] = True
        inventory = defaults.append_controlplain(inventory, None)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][1]['address'])
