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

from kubemarine import demo, audit, packages, apt, yum
from kubemarine.demo import FakeKubernetesCluster


class TestAuditInstallation(unittest.TestCase):

    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA)

    def new_debian_cluster(self) -> FakeKubernetesCluster:
        context = demo.create_silent_context()
        nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        return demo.new_cluster(self.inventory, context=context, nodes_context=nodes_context)

    def get_detect_package_version_cmd(self, os_family: str, package_name: str):
        return packages.get_detect_package_version_cmd(os_family, package_name)

    def test_audit_installation_for_centos(self):
        context = demo.create_silent_context()
        nodes_context = demo.generate_nodes_context(self.inventory, os_name='centos', os_version='7.9')
        cluster = demo.new_cluster(self.inventory, context=context, nodes_context=nodes_context)

        package_associations = cluster.inventory['services']['packages']['associations']['rhel']['audit']

        package_name = package_associations['package_name']
        service_name = package_associations['service_name']

        # simulate package detection command
        exp_results1 = demo.create_nodegroup_result(cluster.nodes['control-plane'], code=1,
                                                    stderr='package %s is not installed' % package_name)
        cluster.fake_shell.add(exp_results1, 'sudo', [self.get_detect_package_version_cmd('rhel', package_name)])

        # simulate package installation command
        installation_command = [yum.get_install_cmd(package_name)]
        exp_results2 = demo.create_nodegroup_result(cluster.nodes['control-plane'],
                                                    code=0, stdout='Successfully installed audit')
        cluster.fake_shell.add(exp_results2, 'sudo', installation_command)

        # simulate enable package command
        exp_results3 = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout='ok')
        cluster.fake_shell.add(exp_results3, 'sudo', ['systemctl enable %s --now' % service_name])

        audit.install(cluster.nodes['control-plane'])

    def test_audit_installation_for_debian(self):
        cluster = self.new_debian_cluster()
        package_associations = cluster.inventory['services']['packages']['associations']['debian']['audit']

        package_name = package_associations['package_name']
        service_name = package_associations['service_name']

        # simulate package detection command
        exp_results1 = demo.create_nodegroup_result(cluster.nodes['control-plane'], code=1,
                                                    stderr='dpkg-query: no packages found matching %s' % package_name)
        cluster.fake_shell.add(exp_results1, 'sudo', [self.get_detect_package_version_cmd('debian', package_name)])

        # simulate package installation command
        installation_command = [apt.get_install_cmd(package_name)]
        exp_results2 = demo.create_nodegroup_result(cluster.nodes['control-plane'],
                                                    code=0, stdout='Successfully installed audit')
        cluster.fake_shell.add(exp_results2, 'sudo', installation_command)

        # simulate enable package command
        exp_results3 = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout='ok')
        cluster.fake_shell.add(exp_results3, 'sudo', ['systemctl enable %s --now' % service_name])

        # run task
        audit.install(cluster.nodes['control-plane'])

    def test_audit_installation_when_already_installed_for_debian(self):
        cluster = self.new_debian_cluster()
        package_associations = cluster.inventory['services']['packages']['associations']['debian']['audit']

        package_name = package_associations['package_name']

        # simulate package detection command
        exp_results = demo.create_nodegroup_result(cluster.nodes['control-plane'], code=0,
                                                   stdout='%s=1:2.8.5-2ubuntu6' % package_name)
        cluster.fake_shell.add(exp_results, 'sudo', [self.get_detect_package_version_cmd('debian', package_name)])

        # run task
        audit.install(cluster.nodes['control-plane'])

    def test_audit_installation_when_partly_installed_for_debian(self):
        cluster = self.new_debian_cluster()
        package_associations = cluster.inventory['services']['packages']['associations']['debian']['audit']

        package_name = package_associations['package_name']
        service_name = package_associations['service_name']

        # simulate package detection command with partly installed audit
        host_to_result = {
            '10.101.1.2': demo.create_result(stdout='%s=1:2.8.5-2ubuntu6' % package_name,
                                             code=0),
            '10.101.1.3': demo.create_result(stderr='dpkg-query: no packages found matching %s' % package_name,
                                             code=1),
            '10.101.1.4': demo.create_result(stdout='%s=1:2.8.5-2ubuntu6' % package_name,
                                             code=0)
        }
        exp_results1 = demo.create_nodegroup_result_by_hosts(cluster, host_to_result)
        cluster.fake_shell.add(exp_results1, 'sudo', [self.get_detect_package_version_cmd('debian', package_name)])

        # simulate package installation command
        installation_command = [apt.get_install_cmd(package_name)]
        exp_results2 = demo.create_nodegroup_result(cluster.nodes['control-plane'],
                                                    code=0, stdout='Successfully installed audit')
        cluster.fake_shell.add(exp_results2, 'sudo', installation_command)

        # simulate enable package command
        enable_command = ['systemctl enable %s --now' % service_name]
        exp_results3 = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout='ok')
        cluster.fake_shell.add(exp_results3, 'sudo', enable_command)

        # run task
        audit.install(cluster.nodes['control-plane'])

        for host in cluster.nodes['control-plane'].get_hosts():
            expected_is_called = host == '10.101.1.3'
            self.assertEqual(expected_is_called, cluster.fake_shell.is_called(host, 'sudo', enable_command),
                             msg="Installation task did not finished with audit enable command")

    def test_audit_configuring(self):
        cluster = self.new_debian_cluster()
        package_associations = cluster.inventory['services']['packages']['associations']['debian']['audit']
        package_name = package_associations['package_name']
        config_location = package_associations['config_location']
        executable_name = package_associations['executable_name']

        cluster.fake_fs.reset()

        expected_data = " \n".join(cluster.inventory['services']['audit']['rules'])

        results = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout='No rules\n', code=0)
        cluster.fake_shell.add(results, 'sudo', [f'{executable_name} -l'], usage_limit=1)

        expected_results = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout=expected_data, code=0)
        cluster.fake_shell.add(expected_results, 'sudo', [f'{executable_name} -l'])

        results = demo.create_nodegroup_result(cluster.nodes['control-plane'], stdout='restarted', code=0)
        cluster.fake_shell.add(results, 'sudo', ['service %s restart' % package_name])

        actual_results = audit.apply_audit_rules(cluster.nodes['control-plane'])

        self.assertEqual(expected_results, actual_results,
                         msg='Configuration task did not did not finished with restart result')

        node_hostname = cluster.nodes['control-plane'].get_hosts()[0]
        actual_data = cluster.fake_fs.read(node_hostname, config_location)

        self.assertEqual(expected_data, actual_data,
                         msg='Audit rules file contains invalid content')


if __name__ == '__main__':
    unittest.main()
