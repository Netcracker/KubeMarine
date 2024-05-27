# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from kubemarine import demo, packages
from kubemarine.core import static
from kubemarine.procedures import install


class ManageMandatoryPackages(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        self.context = demo.create_silent_context()
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        self.mandatory_pkgs_setup = {}
        for package in static.DEFAULTS["services"]["packages"]['mandatory'].keys():
            self.mandatory_pkgs_setup[package] = []
        for node in self.inventory['nodes']:
            host = node['address']
            for pkg in ('conntrack', 'iptables'):
                if 'control-plane' in node['roles'] or 'worker' in node['roles']:
                    self.mandatory_pkgs_setup[pkg].append(host)
            for pkg in ('openssl', 'curl', 'kmod'):
                self.mandatory_pkgs_setup[pkg].append(host)

    def _new_cluster(self):
        cluster = demo.new_cluster(self.inventory, context=self.context, nodes_context=self.nodes_context)
        for node in cluster.nodes['all'].get_ordered_members_list():
            installation_command = self._get_install_cmd(cluster, node.get_host())
            results = demo.create_hosts_result([node.get_host()], stdout=f'Successfully installed')
            cluster.fake_shell.add(results, 'sudo', installation_command)

        return cluster

    def _get_install_cmd(self, cluster: demo.FakeKubernetesCluster, host: str):
        os_family = cluster.get_os_family()
        package_names = []
        for pkg, hosts in self.mandatory_pkgs_setup.items():
            if host in hosts:
                package_names.append(
                    cluster.inventory['services']['packages']['associations'][os_family][pkg]['package_name'])

        return [packages.get_package_manager(cluster.nodes['all']).get_install_cmd(package_names)]

    def _assert_installed(self, cluster: demo.FakeKubernetesCluster):
        for node in cluster.nodes['all'].get_ordered_members_list():
            installation_command = self._get_install_cmd(cluster, node.get_host())
            history = cluster.fake_shell.history_find(node.get_host(), 'sudo', installation_command)
            self.assertTrue(len(history) == 1 and history[0]["used_times"] == 1,
                            "Installation command should be called once")

    def test_default_install_debian(self):
        cluster = self._new_cluster()
        install.system_prepare_package_manager_manage_packages(cluster)
        self._assert_installed(cluster)

    def test_default_install_rhel(self):
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        for node in self.inventory['nodes']:
            self.mandatory_pkgs_setup.setdefault('semanage', []).append(node['address'])
        cluster = self._new_cluster()
        install.system_prepare_package_manager_manage_packages(cluster)
        self._assert_installed(cluster)

    def test_skip_not_managed(self):
        del self.mandatory_pkgs_setup['conntrack']
        del self.mandatory_pkgs_setup['openssl']
        mandatory_section = self.inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('mandatory', {})
        mandatory_section['conntrack'] = False
        mandatory_section['openssl'] = False
        cluster = self._new_cluster()
        install.system_prepare_package_manager_manage_packages(cluster)
        self._assert_installed(cluster)

    def test_install_unzip(self):
        thirdparties = self.inventory.setdefault('services', {}).setdefault('thirdparties', {})
        nodes = ['balancer-1', 'control-plane-2']
        thirdparties['target.zip'] = {
            "source": "source.zip",
            "unpack": "target/dir",
            "nodes": nodes
        }
        for node in self.inventory['nodes']:
            if node['name'] in nodes:
                self.mandatory_pkgs_setup.setdefault('unzip', []).append(node['address'])
        cluster = self._new_cluster()
        install.system_prepare_package_manager_manage_packages(cluster)
        self._assert_installed(cluster)


if __name__ == '__main__':
    unittest.main()
