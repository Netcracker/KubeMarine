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
from typing import List
from test.unit import utils

import yaml

from kubemarine import demo, keepalived, yum
from kubemarine.procedures import install


class TestKeepalivedDefaultsEnrichment(unittest.TestCase):

    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        self.cluster = demo.new_cluster(self.inventory)
        self.cluster2 = demo.new_cluster(self.inventory)

    def test_no_vrrp_ips_defined(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        demo.new_cluster(inventory)

    def test_hosts_auto_detection(self):
        self.assertIn(self.cluster.inventory.get('vrrp_ips')[0]['hosts'][0]['name'], ['balancer-1', 'balancer-2'])
        self.assertIn(self.cluster.inventory.get('vrrp_ips')[0]['hosts'][1]['name'], ['balancer-1', 'balancer-2'])

    def test_vrrp_ips_conversion(self):
        self.assertIsInstance(self.inventory.get('vrrp_ips')[0], str)
        self.assertIsInstance(self.cluster.inventory.get('vrrp_ips')[0], dict)
        self.assertEqual(self.inventory.get('vrrp_ips')[0], self.cluster.inventory.get('vrrp_ips')[0]['ip'])

    def test_auth_interface_detect(self):
        self.assertEqual(self.cluster.inventory.get('vrrp_ips')[0]['hosts'][0]['interface'], 'eth0')

    def test_nondefault_interface_apply(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'interface': 'test'
        }
        cluster = demo.new_cluster(inventory)

        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['interface'], 'test')

    def test_default_router_id_generation(self):
        self.assertIsNotNone(self.cluster.inventory.get('vrrp_ips')[0]['router_id'])
        self.assertTrue(self.cluster.inventory.get('vrrp_ips')[0]['router_id'].isnumeric())
        self.assertEqual(self.cluster.inventory.get('vrrp_ips')[0]['router_id'],
                         self.cluster2.inventory.get('vrrp_ips')[0]['router_id'])

    def test_default_router_id_generation_ipv6(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['::1']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '1')

    def test_default_router_id_generation_ipv6_2(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['::']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '0')

    def test_default_router_id_generation_ipv6_3(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['fdda:5cc1:23:4::f']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '15')

    def test_default_router_id_generation_ipv6_4(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['fdda:5cc1:23:4::1f']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '31')

    def test_default_router_id_generation_ipv6_5(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['fdc8:f4e3:c24a:1403:f816:3eff:fe6b:a082']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '130')

    def test_default_router_id_generation_ipv6_6(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        inventory['vrrp_ips'] = ['2001:db8:1:2:020c:29ff:fe0c:47d5']
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['router_id'], '213')

    def test_default_id_generation(self):
        self.assertIsNotNone(self.cluster.inventory.get('vrrp_ips')[0]['id'])
        self.assertEqual(len(self.cluster.inventory.get('vrrp_ips')[0]['id']),
                         self.cluster.globals['keepalived']['defaults']['label_size'])
        self.assertEqual(self.cluster.inventory.get('vrrp_ips')[0]['id'],
                         self.cluster2.inventory.get('vrrp_ips')[0]['id'])

    def test_default_password_generation(self):
        self.assertIsNotNone(self.cluster.inventory.get('vrrp_ips')[0]['password'])
        self.assertEqual(len(self.cluster.inventory.get('vrrp_ips')[0]['password']),
                         self.cluster.globals['keepalived']['defaults']['password_size'])
        self.assertNotEqual(self.cluster.inventory.get('vrrp_ips')[0]['password'],
                            self.cluster2.inventory.get('vrrp_ips')[0]['password'])

    def test_default_hosts_priority_generation(self):
        self.assertEqual(self.cluster.inventory.get('vrrp_ips')[0]['hosts'][0].get('priority'),
                         self.cluster.globals['keepalived']['defaults']['priority']['max_value'] -
                         self.cluster.globals['keepalived']['defaults']['priority']['step'])
        self.assertEqual(self.cluster.inventory.get('vrrp_ips')[0]['hosts'][1].get('priority'),
                         self.cluster.globals['keepalived']['defaults']['priority']['max_value'] -
                         self.cluster.globals['keepalived']['defaults']['priority']['step'] * 2)

    def test_keepalived_group_appeared(self):
        self.assertIsNotNone(self.cluster.nodes.get('keepalived'))

        balancer_1_ip = self.cluster.nodes['all'].get_member_by_name('balancer-1').get_host()
        self.assertIn(balancer_1_ip, self.cluster.nodes['keepalived'].get_hosts())

    def test_vrrp_defined_no_hosts_and_balancers(self):
        # vrrp_ip defined, but hosts for it is not defined + no balancers to auto determine
        inventory = demo.generate_inventory(balancer=0, control_plane=3, worker=3, keepalived=1)
        # Cluster is enriched with warnings, and the VRRP IP is not taken into account.
        cluster = demo.new_cluster(inventory)

        self.assertTrue(cluster.make_group_from_roles(['keepalived']).is_empty())

        finalized_inventory = utils.make_finalized_inventory(cluster)

        self.assertEqual(1, len(finalized_inventory['vrrp_ips']))
        self.assertEqual([], finalized_inventory['vrrp_ips'][0]['hosts'])

    def test_vrrp_assigned_not_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        first_control_plane = next(node for node in inventory['nodes'] if 'control-plane' in node['roles'])
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'hosts': [first_control_plane['name']]
        }

        cluster = demo.new_cluster(inventory)

        self.assertTrue(cluster.make_group_from_roles(['keepalived']).is_empty())

        finalized_inventory = utils.make_finalized_inventory(cluster)

        self.assertEqual(1, len(finalized_inventory['vrrp_ips']))
        self.assertEqual(1, len(finalized_inventory['vrrp_ips'][0]['hosts']))
        self.assertEqual(first_control_plane['name'], finalized_inventory['vrrp_ips'][0]['hosts'][0]['name'])

    def test_vrrp_remove_only_balancer_enrich_group_finalized_hosts_empty(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        cluster = self._new_remove_node_cluster(inventory, [balancer])

        self.assertEqual([balancer['name']], cluster.get_nodes_for_removal().get_nodes_names(),
                         "Unexpected nodes for removal")
        self.assertEqual([balancer['name']], cluster.get_nodes_for_removal().having_roles(['keepalived']).get_nodes_names(),
                         "Node for removal should present among 'keepalived' group to be removed")
        self.assertEqual([], install.get_keepalived_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure keepalived")

        finalized_inventory = utils.make_finalized_inventory(cluster)

        self.assertEqual(1, len(finalized_inventory['vrrp_ips']))
        self.assertEqual([], finalized_inventory['vrrp_ips'][0]['hosts'])

        self.assertEqual(1, len(cluster.formatted_inventory['vrrp_ips']))
        self.assertEqual(inventory['vrrp_ips'], cluster.formatted_inventory['vrrp_ips'])

    def test_vrrp_assigned_to_removed_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=2, keepalived=2)
        balancers = [node for node in inventory['nodes'] if 'balancer' in node['roles']]
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'hosts': [balancers[0]['name']],
            'floating_ip': '1.1.1.1'
        }
        inventory['vrrp_ips'][1] = {
            'ip': inventory['vrrp_ips'][1],
            'floating_ip': '2.2.2.2'
        }

        cluster = self._new_remove_node_cluster(inventory, [balancers[0]])

        self.assertEqual([balancers[0]['name']], cluster.get_nodes_for_removal().get_nodes_names(),
                         "Unexpected nodes for removal")
        self.assertEqual([balancers[1]['name']], cluster.make_group_from_roles(['keepalived']).get_nodes_names(),
                         "Node for removal should not present among 'keepalived' group")
        self.assertEqual([balancers[1]['name']], install.get_keepalived_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure keepalived")

        finalized_inventory = utils.make_finalized_inventory(cluster)

        self.assertEqual(2, len(finalized_inventory['vrrp_ips']))
        self.assertEqual(1, len(finalized_inventory['vrrp_ips'][0]['hosts']))
        self.assertEqual(balancers[0]['name'], finalized_inventory['vrrp_ips'][0]['hosts'][0]['name'])
        self.assertEqual(1, len(finalized_inventory['vrrp_ips'][1]['hosts']))
        self.assertEqual(balancers[1]['name'], finalized_inventory['vrrp_ips'][1]['hosts'][0]['name'])

        self.assertEqual(2, len(cluster.formatted_inventory['vrrp_ips']))
        self.assertEqual(inventory['vrrp_ips'], cluster.formatted_inventory['vrrp_ips'])

    def test_remove_and_add_only_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        cluster = self._new_remove_node_cluster(inventory, [balancer])

        self.assertEqual([], cluster.make_group_from_roles(['keepalived']).get_nodes_names(),
                         "Node for removal should not present among 'keepalived' group")
        self.assertEqual([], install.get_keepalived_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure keepalived")

        cluster = self._new_add_node_cluster(cluster.formatted_inventory, [balancer])

        self.assertEqual([balancer['name']], cluster.make_group_from_roles(['keepalived']).get_nodes_names(),
                         "New nodes should present among 'keepalived' group")
        self.assertEqual([balancer['name']], install.get_keepalived_configure_group(cluster).get_nodes_names(),
                         "Unexpected nodes to reconfigure keepalived")

    def _new_remove_node_cluster(self, inventory: dict, nodes: List[dict]) -> demo.FakeKubernetesCluster:
        context = demo.create_silent_context(['fake.yaml', '--without-act'], procedure='remove_node')
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = nodes
        return demo.new_cluster(inventory, context=context, procedure_inventory=procedure_inventory)

    def _new_add_node_cluster(self, inventory: dict, nodes: List[dict]) -> demo.FakeKubernetesCluster:
        context = demo.create_silent_context(['fake.yaml', '--without-act'], procedure='add_node')
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = nodes
        return demo.new_cluster(inventory, context=context, procedure_inventory=procedure_inventory)

    def test_two_vrrp_different_interfaces(self):
        scheme = demo.new_scheme(demo.ALLINONE, 'keepalived', 2)
        inventory = demo.generate_inventory(**scheme)
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'interface': 'inf1'
        }
        inventory['vrrp_ips'][1] = {
            'ip': inventory['vrrp_ips'][1],
            'interface': 'inf2'
        }

        cluster = demo.new_cluster(inventory)

        self.assertEqual(cluster.inventory.get('vrrp_ips')[0]['hosts'][0]['interface'], 'inf1')
        self.assertEqual(cluster.inventory.get('vrrp_ips')[1]['hosts'][0]['interface'], 'inf2')

    def test_password_enrich_exponential_float(self):
        # Make sure to execute global patches of environment / libraries
        from kubemarine import __main__  # pylint: disable=unused-import

        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        ip = inventory['vrrp_ips'][0]
        inventory['vrrp_ips'][0] = {
            'ip': ip,
            'password': '952184e0'
        }
        cluster = demo.new_cluster(inventory)

        finalized_inventory = utils.make_finalized_inventory(cluster)
        finalized_dumped = yaml.dump(finalized_inventory)
        self.assertIn("'952184e0'", finalized_dumped)

        finalized_as_input = yaml.safe_load(finalized_dumped)
        cluster = demo.new_cluster(finalized_as_input)
        self.assertEqual('952184e0', cluster.inventory['vrrp_ips'][0]['password'])


class TestKeepalivedInstallation(unittest.TestCase):

    def test_keepalived_installation_when_already_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['keepalived']

        # simulate already installed keepalived package
        expected_results_1 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='Keepalived v1.2.3')
        cluster.fake_shell.add(expected_results_1, 'sudo', ['%s -v' % package_associations['executable_name']])

        # simulate mkdir command
        expected_results_2 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_2, 'sudo', ["mkdir -p /etc/systemd/system/keepalived.service.d"])

        # simulate systemd daemon reload
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["systemctl daemon-reload"])

        # simulate chmod command
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_4, 'sudo', ['chmod +x /usr/local/bin/check_haproxy.sh'])

        # simulate enable package command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo',
                               ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = keepalived.install(cluster.nodes['keepalived'])

        # verify installation result should be the same as simulated and contain version print stdout
        self.assertEqual(expected_results_1, actual_result)

    def test_keepalived_installation_when_not_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['keepalived']

        # simulate keepalived package missing
        missing_package_command = ['%s -v' % package_associations['executable_name']]
        missing_package_result = demo.create_nodegroup_result(cluster.nodes['keepalived'],
                                                              code=127, stderr='Command keepalived not found')
        cluster.fake_shell.add(missing_package_result, 'sudo', missing_package_command)

        # simulate package installation
        installation_command = [yum.get_install_cmd(cluster, package_associations['package_name'])]
        expected_results = demo.create_nodegroup_result(cluster.nodes['keepalived'], code=0,
                                                        stdout='Successfully installed keepalived')
        cluster.fake_shell.add(expected_results, 'sudo', installation_command)

        # simulate package installation check command
        check_command = [f'rpm -q {package_associations["package_name"]}']
        expected_results_1 = demo.create_nodegroup_result(cluster.nodes['balancer'], code=0,
                                                          stdout='All packages installed')
        cluster.fake_shell.add(expected_results_1, 'sudo', check_command)

        # simulate mkdir command
        expected_results_2 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_2, 'sudo', ["mkdir -p /etc/systemd/system/keepalived.service.d"])

        # simulate systemd daemon reload
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["systemctl daemon-reload"])

        # simulate chmod command
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_4, 'sudo', ['chmod +x /usr/local/bin/check_haproxy.sh'])

        # simulate enable package command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo',
                               ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = keepalived.install(cluster.nodes['keepalived'])

        # verify installation result should be the same as simulated and contain version print stdout
        self.assertEqual(expected_results, actual_result)


class TestKeepalivedConfigGeneration(unittest.TestCase):

    def test_skip_vrrp_not_assigned(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=2, keepalived=2)
        first_balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'hosts': [first_balancer['name']],
        }

        cluster = demo.new_cluster(inventory)
        enriched_vrrp_ips = cluster.inventory['vrrp_ips']

        balancers = cluster.nodes['balancer'].get_ordered_members_configs_list()

        config_1 = keepalived.generate_config(cluster, balancers[0])
        self.assertIn(f"vrrp_instance balancer_{enriched_vrrp_ips[0]['id']}", config_1)
        self.assertIn(f"vrrp_instance balancer_{enriched_vrrp_ips[1]['id']}", config_1)

        config_2 = keepalived.generate_config(cluster, balancers[1])
        self.assertNotIn(f"vrrp_instance balancer_{enriched_vrrp_ips[0]['id']}", config_2)
        self.assertIn(f"vrrp_instance balancer_{enriched_vrrp_ips[1]['id']}", config_2)

    def test_skip_removed_peers(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=3, keepalived=1)
        first_balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [first_balancer]

        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context)

        balancers = cluster.previous_nodes['balancer'].get_ordered_members_configs_list()

        only_left_peer_template = """\
    unicast_peer {{
        {peer}
    }}"""

        config_2 = keepalived.generate_config(cluster, balancers[1])
        self.assertIn(only_left_peer_template.format(peer=balancers[2]['internal_address']), config_2)

        config_3 = keepalived.generate_config(cluster, balancers[2])
        self.assertIn(only_left_peer_template.format(peer=balancers[1]['internal_address']), config_3)

    def test_default_global_defs(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        first_balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        cluster = demo.new_cluster(inventory)

        config_1 = keepalived.generate_config(cluster, first_balancer)
        self.assertNotIn("global_defs", config_1)

    def test_default_overriden_global_defs(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        first_balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        vrrp_garp_master_refresh = 60
        inventory['services'] = {
            "loadbalancer": {
                "keepalived": {
                    "global": {
                        "vrrp_garp_master_refresh": vrrp_garp_master_refresh
                    }
                }
            }
        }

        cluster = demo.new_cluster(inventory)
        only_vrrp_garp_template = """\
global_defs {{
    vrrp_garp_master_refresh {vrrp_garp_master_refresh}
}}"""
        config_1 = keepalived.generate_config(cluster, first_balancer)
        self.assertIn(only_vrrp_garp_template.format(vrrp_garp_master_refresh=vrrp_garp_master_refresh), config_1)


class TestKeepalivedConfigApply(unittest.TestCase):

    def test_config_apply(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        node = cluster.nodes['keepalived'].get_first_member()
        expected_config = keepalived.generate_config(cluster, node.get_config())

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['keepalived']
        configs_directory = '/'.join(package_associations['config_location'].split('/')[:-1])

        # simulate mkdir for configs
        cluster.fake_shell.add(demo.create_nodegroup_result(cluster.nodes['keepalived'], code=0), 'sudo',
                               ['mkdir -p %s' % configs_directory])

        # simulate configs ls -la
        cluster.fake_shell.add(demo.create_nodegroup_result(cluster.nodes['keepalived'], code=0), 'sudo',
                               ['ls -la %s' % package_associations['config_location']])

        # simulate daemon restart
        cluster.fake_shell.add(demo.create_nodegroup_result(cluster.nodes['keepalived'], code=0), 'sudo',
                               ['systemctl restart %s' % package_associations['service_name']])

        # simulate daemon status
        simulated_result = demo.create_nodegroup_result(cluster.nodes['keepalived'], code=0)
        cluster.fake_shell.add(simulated_result, 'sudo', ['systemctl status %s' % package_associations['service_name']])

        actual_result = keepalived.configure(cluster.nodes['keepalived'])

        self.assertEqual(simulated_result, actual_result)

        # read placed data in FakeFS
        actual_config = cluster.fake_fs.read(node.get_host(), package_associations['config_location'])

        self.assertEqual(expected_config, actual_config)


if __name__ == '__main__':
    unittest.main()
