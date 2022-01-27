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

from kubemarine import haproxy
from kubemarine import demo


class HAProxyDefaultsEnrichment(unittest.TestCase):

    def test_correct_inventory(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        print("Inventory: " + str(inventory))
        cluster = demo.new_cluster(inventory)
        haproxy.enrich_inventory(cluster.inventory, None)

    def test_inventory_verify_multirole_balancer_without_keepalived(self):
        inventory = demo.generate_inventory(master=3, balancer=['master-1', 'master-2', 'master-3'],
                                            worker=['master-1', 'master-2', 'master-3'], keepalived=0)

        print("Inventory: " + str(inventory))

        with self.assertRaises(Exception) as cm:
            demo.new_cluster(inventory)

        self.assertIn(haproxy.ERROR_VRRP_IS_NOT_CONFIGURED, str(cm.exception), "Invalid exception message")


class TestHaproxyInstallation(unittest.TestCase):

    def test_haproxy_installation_when_already_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['haproxy']

        # simulate already installed haproxy package
        expected_results_1 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='Haproxy v1.2.3')
        cluster.fake_shell.add(expected_results_1, 'sudo', ['%s -v' % package_associations['executable_name']])

        # simulate mkdir command
        expected_results_2 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_2, 'sudo', ["mkdir -p /etc/systemd/system/rh-haproxy18-haproxy.service.d"])

        # simulate systemd daemon reload
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["systemctl daemon-reload"])

        # simulate enable package command
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='ok')
        cluster.fake_shell.add(expected_results_4, 'sudo', ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = haproxy.install(cluster.nodes['balancer'])

        # verify installation result should be the same as simulated and contain version print stdout
        expected_results_1 = cluster.nodes["all"]._make_result(expected_results_1)

        # TODO: this section is not compatible with RemoteExecutor yet
        # self.assertEqual(expected_results, actual_result)

    def test_haproxy_installation_when_not_installed(self):
        inventory = demo.generate_inventory(**demo.FULLHA)
        cluster = demo.new_cluster(inventory)

        package_associations = cluster.inventory['services']['packages']['associations']['haproxy']

        # simulate haproxy package missing
        missing_package_command = ['%s -v' % package_associations['executable_name']]
        missing_package_result = demo.create_nodegroup_result(cluster.nodes['balancer'],
                                                              code=127, stderr='Command haproxy not found')
        cluster.fake_shell.add(missing_package_result, 'sudo', missing_package_command)

        # simulate package installation
        installation_command = ['yum install -y %s; rpm -q %s; if [ $? != 0 ]; then echo '
                                '\"Failed to check version for some packages. '
                                'Make sure packages are not already installed with higher versions. '
                                'Also, make sure user-defined packages have rpm-compatible names. \"; exit 1; fi '
                                % (package_associations['package_name'], package_associations['package_name'])]
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

        # simulate systemd daemon reload
        expected_results_3 = demo.create_nodegroup_result(cluster.nodes['balancer'])
        cluster.fake_shell.add(expected_results_3, 'sudo', ["systemctl daemon-reload"])

        # simulate enable package command
        expected_results_4 = demo.create_nodegroup_result(cluster.nodes['balancer'], stdout='ok')
        cluster.fake_shell.add(expected_results_4, 'sudo', ['systemctl enable %s --now' % package_associations['service_name']])

        # start installation
        actual_result = haproxy.install(cluster.nodes['balancer'])

        # verify installation result should be the same as simulated and contain version print stdout
        expected_results = get_result_str(expected_results)

        self.assertEqual(expected_results, actual_result)


def get_result_str(results):
    output = ""
    for host, result in results.items():
        if output != "":
            output += "\n"
        output += "\t%s (%s): code=%i" % (host.host, 0, result.exited)
        if result.stdout:
            output += "\n\t\tSTDOUT: %s" % result.stdout.replace("\n", "\n\t\t        ")
        if result.stderr:
            output += "\n\t\tSTDERR: %s" % result.stderr.replace("\n", "\n\t\t        ")

    return output


if __name__ == '__main__':
    unittest.main()
