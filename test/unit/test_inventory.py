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
import copy
import re
import unittest
from copy import deepcopy
from test.unit import utils as test_utils

from kubemarine import demo
from kubemarine.core import errors


class TestInventoryValidation(unittest.TestCase):

    def test_labels_check(self):
        inventory = demo.generate_inventory(control_plane=1, balancer=1, worker=0)
        for node in inventory['nodes']:
            if 'balancer' in node['roles']:
                node["labels"] = {"should": "fail"}
        with self.assertRaises(Exception) as context:
            demo.new_cluster(inventory)

        self.assertIn("Only 'worker' or 'control-plane' nodes can have labels", str(context.exception))

    def test_taints_check(self):
        inventory = demo.generate_inventory(control_plane=1, balancer=1, worker=0)
        for node in inventory['nodes']:
            if 'balancer' in node['roles']:
                node["taints"] = ["should fail"]
        with self.assertRaises(Exception) as context:
            demo.new_cluster(inventory)

        self.assertIn("Only 'worker' or 'control-plane' nodes can have taints", str(context.exception))

    def test_invalid_node_name(self):
        inventory = demo.generate_inventory(control_plane=1, balancer=0, worker=0)
        inventory["nodes"][0]["name"] = "bad_node/name"

        with self.assertRaises(Exception):
            demo.new_cluster(inventory)

    def test_correct_node_name(self):
        inventory = demo.generate_inventory(control_plane=1, balancer=0, worker=0)
        inventory["nodes"][0]["name"] = "correct-node.name123"
        demo.new_cluster(inventory)

    def test_missed_roles(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        del inventory['nodes'][0]['roles']
        with self.assertRaisesRegex(errors.FailException, r"'roles' is a required property"):
            demo.new_cluster(inventory)

    def test_not_supported_role(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['nodes'][0]['roles'] = ['test']
        with self.assertRaisesRegex(errors.FailException,
                                    re.escape("Value should be one of ['worker', 'control-plane', 'master', 'balancer']")):
            demo.new_cluster(inventory)

    def test_not_supported_master_role(self):
        inventory = demo.generate_inventory(control_plane=2, worker=0, balancer=0)
        inventory['nodes'][0]['roles'] = ['master']
        with self.assertRaisesRegex(errors.FailException,
                                    re.escape("Value should be one of ['worker', 'control-plane', 'balancer']")):
            demo.new_cluster(inventory)

    def test_explicitly_added_service_role(self):
        error_regex = r"Value should be one of \['worker', 'control-plane', 'master', 'balancer']"
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['nodes'][1]['roles'].append('add_node')
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [inventory['nodes'].pop(0)]
        with self.assertRaisesRegex(errors.FailException, error_regex):
            demo.new_cluster(inventory, context=context, procedure_inventory=procedure_inventory)

        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['nodes'][1]['roles'].append('remove_node')
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [inventory['nodes'][0]]
        with self.assertRaisesRegex(errors.FailException, error_regex):
            demo.new_cluster(inventory, context=context, procedure_inventory=procedure_inventory)

    def test_remove_node_invalid_specification(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [inventory['nodes'][0]['name']]
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'string'\. Expected: 'object'"):
            demo.new_cluster(deepcopy(inventory), context=deepcopy(context), procedure_inventory=deepcopy(procedure_inventory))

        procedure_inventory['nodes'] = [{}]
        with self.assertRaisesRegex(errors.FailException, r"'name' is a required property"):
            demo.new_cluster(deepcopy(inventory), context=deepcopy(context), procedure_inventory=procedure_inventory)

    def test_empty_roles_node_names(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['nodes'][0]['roles'] = []
        del inventory['nodes'][0]['name']
        with self.assertRaisesRegex(errors.FailException, r"Number of items equal to 0 is less than the minimum of 1"):
            demo.new_cluster(inventory)

    def test_missed_any_address(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        context = demo.create_silent_context()
        nodes_context = demo.generate_nodes_context(inventory)
        del inventory['nodes'][0]['address']
        del inventory['nodes'][0]['internal_address']
        with self.assertRaisesRegex(errors.FailException, r"'internal_address' is a required property"):
            resources = demo.FakeResources(context, inventory, nodes_context=nodes_context)
            resources.cluster()

    def test_mix_registry_approaches(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['registry'] = {
            'endpoints': ['one'],
            'docker_port': 1000
        }
        with self.assertRaisesRegex(errors.FailException, r"'docker_port' was unexpected"):
            demo.new_cluster(inventory)

    def test_registry_unexpected_endpoints_format(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['registry'] = {
            'endpoints': [True],
        }
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'boolean'. Expected: 'string'"):
            demo.new_cluster(inventory)

    def test_apparmor_unexpected_state(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['kernel_security'] = {
            'apparmor': {"unexpected_state": []}
        }
        with self.assertRaisesRegex(errors.FailException, r"'unexpected_state' was unexpected"):
            demo.new_cluster(inventory)

    def test_selinux_unexpected_state(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['kernel_security'] = {
            'selinux': {"state": 'unexpected'}
        }
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enforcing', 'permissive', 'disabled']"):
            demo.new_cluster(inventory)

    def test_selinux_unexpected_policy(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['kernel_security'] = {
            'selinux': {"policy": 'unexpected'}
        }
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['targeted', 'strict']"):
            demo.new_cluster(inventory)

    def test_old_docker_declaration(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['docker'] = {}
        with self.assertRaisesRegex(errors.FailException, r"'docker' was unexpected"):
            demo.new_cluster(inventory)

    def test_unexpected_container_runtime(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri'] = {
            'containerRuntime': 'unexpected'
        }
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['containerd']"):
            demo.new_cluster(inventory)

    def test_account_name_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('rbac', {})['accounts'] = [
            {'role': 'cluster-admin'}
        ]
        with self.assertRaisesRegex(errors.FailException, r"'name' is a required property"):
            demo.new_cluster(inventory)

    def test_account_role_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('rbac', {})['accounts'] = [
            {'name': 'superadmin'}
        ]
        with self.assertRaisesRegex(errors.FailException, r"'role' is a required property"):
            demo.new_cluster(inventory)

    def test_valid_accounts(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('rbac', {})['accounts'] = [
            {'name': 'superadmin', 'role': 'cluster-admin'}
        ]
        demo.new_cluster(inventory)

    def test_new_group_from_nodes(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)
        group = cluster.create_group_from_groups_nodes_names([], ['balancer-1', 'control-plane-1'])
        self.assertEqual(2, len(group.nodes))

        node_names = group.get_nodes_names()
        self.assertIn('balancer-1', node_names)
        self.assertIn('control-plane-1', node_names)

    def test_new_group_from_groups(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)
        group = cluster.create_group_from_groups_nodes_names(['control-plane', 'balancer'], [])
        self.assertEqual(5, len(group.nodes))

        node_names = group.get_nodes_names()
        self.assertIn('balancer-1', node_names)
        self.assertIn('balancer-2', node_names)
        self.assertIn('control-plane-1', node_names)
        self.assertIn('control-plane-2', node_names)
        self.assertIn('control-plane-3', node_names)

    def test_new_group_from_nodes_and_groups_multi(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)
        group = cluster.create_group_from_groups_nodes_names(['control-plane'], ['balancer-1'])
        self.assertEqual(4, len(group.nodes))

        node_names = group.get_nodes_names()
        self.assertIn('balancer-1', node_names)
        self.assertIn('control-plane-1', node_names)
        self.assertIn('control-plane-2', node_names)
        self.assertIn('control-plane-3', node_names)

    def test_roles_in_inventory(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        nodes = cluster.nodes['control-plane'].get_ordered_members_list()
        self.assertEqual(3, len(nodes))
        nodes = cluster.nodes['control-plane'].get_ordered_members_list()
        self.assertEqual(3, len(nodes))

    def test_internal_address_inventory(self):
        inventory = demo.generate_inventory()
        for node in inventory['nodes']:
            node.pop('address')

        cluster = demo.new_cluster(inventory)
        for node in cluster.inventory['nodes']:
            self.assertNotIn('address', node)

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        for node in finalized_inventory['nodes']:
            self.assertNotIn('address', node)

    def test_internal_address_remove_node_inventory(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        for node in inventory['nodes']:
            node.pop('address')
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [copy.deepcopy(inventory['nodes'][0])]

        # Remove node inventory
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        cluster = demo.new_cluster(inventory, procedure_inventory=procedure_inventory, context=context)
        for node in cluster.inventory['nodes']:
            self.assertNotIn('address', node)

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        for node in finalized_inventory['nodes']:
            self.assertNotIn('address', node)

        for node in cluster.formatted_inventory['nodes']:
            self.assertNotIn('address', node)

    def test_internal_address_add_node_inventory(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        for node in inventory['nodes']:
            node.pop('address')

        # Add node inventory
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [inventory['nodes'].pop(0)]
        cluster = demo.new_cluster(inventory, procedure_inventory=procedure_inventory, context=context)
        for node in cluster.inventory['nodes']:
            self.assertNotIn('address', node)

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        for node in finalized_inventory['nodes']:
            self.assertNotIn('address', node)

        for node in cluster.formatted_inventory['nodes']:
            self.assertNotIn('address', node)

    def test_allow_omitted_name(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        for node in inventory['nodes']:
            del node['name']

        cluster = demo.new_cluster(inventory)
        names = [node['name'] for node in cluster.inventory['nodes']]
        self.assertEqual(['balancer-1', 'balancer-2',
                          'control-plane-1', 'control-plane-2', 'control-plane-3',
                          'worker-1', 'worker-2', 'worker-3'], names)

    def test_target_host_ports_generation(self):
        # services.loadbalancer.target_ports default value depends on nodes configuration in cluster
        # This check validates, that default value is calculated correctly for different schemas

        # All-in-one without balancers
        inventory = demo.generate_inventory(balancer=0, worker=1, control_plane=1)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(80, int(cluster.inventory['services']['loadbalancer']['target_ports']['http']))
        self.assertEqual(443, int(cluster.inventory['services']['loadbalancer']['target_ports']['https']))
        self.assertEqual(80, int(next(filter(
            lambda port: port['name'] == 'http',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))
        self.assertEqual(443, int(next(filter(
            lambda port: port['name'] == 'https',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))

        # All-in-one with balancer
        inventory = demo.generate_inventory(**demo.ALLINONE)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(20080, int(cluster.inventory['services']['loadbalancer']['target_ports']['http']))
        self.assertEqual(20443, int(cluster.inventory['services']['loadbalancer']['target_ports']['https']))
        self.assertEqual(20080, int(next(filter(
            lambda port: port['name'] == 'http',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))
        self.assertEqual(20443, int(next(filter(
            lambda port: port['name'] == 'https',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))

        # MinHA
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(20080, int(cluster.inventory['services']['loadbalancer']['target_ports']['http']))
        self.assertEqual(20443, int(cluster.inventory['services']['loadbalancer']['target_ports']['https']))
        self.assertEqual(20080, int(next(filter(
            lambda port: port['name'] == 'http',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))
        self.assertEqual(20443, int(next(filter(
            lambda port: port['name'] == 'https',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))

        # FullHA
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(20080, int(cluster.inventory['services']['loadbalancer']['target_ports']['http']))
        self.assertEqual(20443, int(cluster.inventory['services']['loadbalancer']['target_ports']['https']))
        self.assertEqual(20080, int(next(filter(
            lambda port: port['name'] == 'http',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))
        self.assertEqual(20443, int(next(filter(
            lambda port: port['name'] == 'https',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))

        # FullHA without balancers
        inventory = demo.generate_inventory(**demo.FULLHA_NOBALANCERS)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(80, int(cluster.inventory['services']['loadbalancer']['target_ports']['http']))
        self.assertEqual(443, int(cluster.inventory['services']['loadbalancer']['target_ports']['https']))
        self.assertEqual(80, int(next(filter(
            lambda port: port['name'] == 'http',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))
        self.assertEqual(443, int(next(filter(
            lambda port: port['name'] == 'https',
            cluster.inventory['plugins']['nginx-ingress-controller']['ports']))['hostPort']))

    def test_use_proxy_protocol_generation(self):
        # plugins.nginx-ingress-controller.config_map.use-proxy-protocol default value depends on nodes configuration in cluster
        # This check validates, that default value is calculated correctly for different schemas

        # All-in-one without balancers
        inventory = demo.generate_inventory(balancer=0, worker=1, control_plane=1)
        cluster = demo.new_cluster(inventory)
        self.assertEqual('false', cluster.inventory['plugins']['nginx-ingress-controller']['config_map']['use-proxy-protocol'])

        # All-in-one with balancer
        inventory = demo.generate_inventory(**demo.ALLINONE)
        cluster = demo.new_cluster(inventory)
        self.assertEqual('true', cluster.inventory['plugins']['nginx-ingress-controller']['config_map']['use-proxy-protocol'])

        # MinHA
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        self.assertEqual('true', cluster.inventory['plugins']['nginx-ingress-controller']['config_map']['use-proxy-protocol'])

        # FullHA
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)
        self.assertEqual('true', cluster.inventory['plugins']['nginx-ingress-controller']['config_map']['use-proxy-protocol'])

        # FullHA without balancers
        inventory = demo.generate_inventory(**demo.FULLHA_NOBALANCERS)
        cluster = demo.new_cluster(inventory)
        self.assertEqual('false', cluster.inventory['plugins']['nginx-ingress-controller']['config_map']['use-proxy-protocol'])

    def test_allow_missed_procedure(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        for procedure in ('backup', 'check_paas', 'migrate_kubemarine', 'reboot'):
            context = demo.create_silent_context(procedure=procedure)

            # No exception should be thrown
            demo.new_cluster(deepcopy(inventory), procedure_inventory=None, context=context)

    def test_enrich_certsans_with_custom(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        first_node_name = inventory['nodes'][0]['name']
        inventory['services'].setdefault('kubeadm', {}).setdefault('apiServer', {})['certSANs'] = [
            first_node_name, 'custom'
        ]

        cluster = demo.new_cluster(inventory)
        certsans = cluster.inventory["services"]["kubeadm"]['apiServer']['certSANs']
        self.assertIn('custom', certsans)
        self.assertEqual(1, len([san for san in certsans if san == first_node_name]))

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        certsans = finalized_inventory["services"]["kubeadm"]['apiServer']['certSANs']

        self.assertIn('custom', certsans)
        self.assertEqual(1, len([san for san in certsans if san == first_node_name]))


if __name__ == '__main__':
    unittest.main()
