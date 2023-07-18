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

import yaml

from kubemarine import demo, keepalived, yum
from test.unit import utils


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

    def test_keepalived_role_appeared(self):
        self.assertIn('keepalived', self.cluster.roles)

    def test_keepalived_group_appeared(self):
        self.assertIsNotNone(self.cluster.nodes.get('keepalived'))

        balancer_1_ip = self.cluster.nodes['all'].get_member_by_name('balancer-1').get_host()
        self.assertIn(balancer_1_ip, self.cluster.nodes['keepalived'].get_hosts())

    def test_vrrp_defined_no_hosts_and_balancers(self):
        # vrrp_ip defined, but hosts for it is not defined + no balancers to auto determine -> then raise exception
        inventory = demo.generate_inventory(balancer=0, master=3, worker=3, keepalived=1)
        with self.assertRaises(Exception):
            demo.new_cluster(inventory)

    def test_password_enrich_exponential_float(self):
        # Make sure to execute global patches of environment / libraries
        from kubemarine import __main__

        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        ip = inventory['vrrp_ips'][0]
        inventory['vrrp_ips'][0] = {
            'ip': ip,
            'password': '952184e0'
        }
        cluster = demo.new_cluster(inventory)

        utils.stub_associations_packages(cluster, {})
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

        # simulate chcon command
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["chcon -u system_u /etc/systemd/system/keepalived.service.d"])

        # simulate systemd daemon reload
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_4, 'sudo', ["systemctl daemon-reload"])

        # simulate chmod command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo', ['chmod +x /usr/local/bin/check_haproxy.sh'])

        # simulate enable package command
        expected_results_6 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_6, 'sudo',
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
        installation_command = [yum.get_install_cmd(package_associations['package_name'])]
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

        # simulate chcon command
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["chcon -u system_u /etc/systemd/system/keepalived.service.d"])

        # simulate systemd daemon reload
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_4, 'sudo', ["systemctl daemon-reload"])

        # simulate chmod command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo', ['chmod +x /usr/local/bin/check_haproxy.sh'])

        # simulate enable package command
        expected_results_6 = demo.create_nodegroup_result(cluster.nodes['keepalived'], stdout='ok')
        cluster.fake_shell.add(expected_results_6, 'sudo',
                               ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = keepalived.install(cluster.nodes['keepalived'])

        # verify installation result should be the same as simulated and contain version print stdout
        self.assertEqual(expected_results, actual_result)


class TestKeepalivedConfigGeneration(unittest.TestCase):

    def test_(self):
        # TODO: add test, where keepalived config generated, parsed and verified
        pass


class TestKeepalivedConfigApply(unittest.TestCase):

    def test_config_apply(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        node = cluster.nodes['keepalived'].get_first_member()
        expected_config = keepalived.generate_config(cluster.inventory, node.get_config())

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
