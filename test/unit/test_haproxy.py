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

from kubemarine import haproxy, yum
from kubemarine import demo
from kubemarine.core.group import NodeGroupResult


class HAProxyDefaultsEnrichment(unittest.TestCase):

    def test_correct_inventories(self):
        correct_schemes = [
            demo.MINIHA_KEEPALIVED,
            demo.FULLHA_KEEPALIVED,
            demo.ALLINONE,
            demo.NON_HA_BALANCER,
        ]
        for schema in correct_schemes:
            for try_mntc in (False, True):
                if try_mntc:
                    schema = demo.new_scheme(schema, 'haproxy_mntc', 1)

                inventory = demo.generate_inventory(**schema)
                print("Inventory: " + str(inventory))
                # enrichment should not fail
                demo.new_cluster(inventory)

    def test_incorrect_inventory_without_keepalived(self):
        incorrect_schemes = [
            demo.new_scheme(demo.MINIHA_KEEPALIVED, 'keepalived', 0),
            demo.new_scheme(demo.ALLINONE, 'keepalived', 0),
        ]
        for schema in incorrect_schemes:
            for try_mntc in (False, True):
                if try_mntc:
                    schema = demo.new_scheme(schema, 'haproxy_mntc', 1)
                inventory = demo.generate_inventory(**schema)
                print("Inventory: " + str(inventory))

                with self.assertRaises(Exception) as cm:
                    demo.new_cluster(inventory)

                if try_mntc:
                    self.assertEqual(haproxy.ERROR_NO_BOUND_VRRP_CONFIGURED_MNTC % 'master-1', str(cm.exception),
                                     "Invalid exception message")
                else:
                    self.assertEqual(haproxy.ERROR_VRRP_IS_NOT_CONFIGURED % 'master-1', str(cm.exception),
                                     "Invalid exception message")


class TestHaproxyInstallation(unittest.TestCase):

    def test_haproxy_installation_when_already_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['haproxy']

        # simulate already installed haproxy package
        expected_results_1 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='Haproxy v1.2.3')
        cluster.fake_shell.add(expected_results_1, 'sudo', ['%s -v' % package_associations['executable_name']])

        # simulate mkdir command
        expected_results_2 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_2, 'sudo', ["mkdir -p /etc/systemd/system/rh-haproxy18-haproxy.service.d"])

        # simulate chcon command
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["chcon -u system_u /etc/systemd/system/rh-haproxy18-haproxy.service.d"])

        # simulate systemd daemon reload
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_4, 'sudo', ["systemctl daemon-reload"])

        # simulate enable package command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo', ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = haproxy.install(cluster.nodes['balancer'])

        # verify installation result should be the same as simulated and contain version print stdout
        self.assertEqual(expected_results_1, actual_result)

    def test_haproxy_installation_when_not_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['haproxy']

        # simulate haproxy package missing
        missing_package_command = ['%s -v' % package_associations['executable_name']]
        missing_package_result = demo.create_nodegroup_result(cluster.nodes['balancer'],
                                                              code=127, stderr='Command haproxy not found')
        cluster.fake_shell.add(missing_package_result, 'sudo', missing_package_command)

        # simulate package installation
        installation_command = [yum.get_install_cmd(package_associations['package_name'])]
        expected_results = demo.create_nodegroup_result(cluster.nodes['balancer'], code=0,
                                                        stdout='Successfully installed haproxy')
        cluster.fake_shell.add(expected_results, 'sudo', installation_command)

        # simulate package installation check command
        check_command = [f'rpm -q {package_associations["package_name"]}']
        expected_results_1 = demo.create_nodegroup_result(cluster.nodes['balancer'], code=0,
                                                          stdout='All packages installed')
        cluster.fake_shell.add(expected_results_1, 'sudo', check_command)

        # simulate mkdir command
        expected_results_2 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_2, 'sudo', ["mkdir -p /etc/systemd/system/rh-haproxy18-haproxy.service.d"])

        # simulate chcon command
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["chcon -u system_u /etc/systemd/system/rh-haproxy18-haproxy.service.d"])

        # simulate systemd daemon reload
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_4, 'sudo', ["systemctl daemon-reload"])

        # simulate enable package command
        expected_results_5 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='ok')
        cluster.fake_shell.add(expected_results_5, 'sudo', ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = haproxy.install(cluster.nodes['balancer'])

        # verify installation result should be the same as simulated and contain version print stdout
        self.assertEqual(expected_results, actual_result)


if __name__ == '__main__':
    unittest.main()
