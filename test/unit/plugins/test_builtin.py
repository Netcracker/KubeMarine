# Copyright 2021-2023 NetCracker Technology Corporation
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

from kubemarine import demo
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Identity


class ManifestsInstallationTest(unittest.TestCase):
    def test_get_pss_profiles_manifests_default(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        cluster = demo.new_cluster(inventory)

        expected_install_manifests = {
            Identity("calico"): True,
            Identity("calico", "apiserver"): False,
            Identity("nginx-ingress-controller"): True,
            Identity("kubernetes-dashboard"): False,
            Identity("local-path-provisioner"): False,
        }
        for id_, expected_installed in expected_install_manifests.items():
            self.assertEqual(expected_installed, builtin.is_manifest_installed(cluster, id_),
                             f"Manifest {id_.name!r} is {'not' if expected_installed else 'unexpectedly'} to be installed")

        expected_pss_profiles = {
            'ingress-nginx': 'privileged',
        }
        self.assertEqual(expected_pss_profiles, builtin.get_namespace_to_necessary_pss_profiles(cluster),
                         "Unexpected minimal PSS profiles for plugins' namespaces")

    def test_get_pss_profiles_manifests_full(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        plugins = inventory.setdefault('plugins', {})
        plugins.setdefault('kubernetes-dashboard', {})['install'] = True
        plugins.setdefault('local-path-provisioner', {})['install'] = True
        plugins.setdefault('calico', {}).setdefault('apiserver', {})['enabled'] = True
        cluster = demo.new_cluster(inventory)

        expected_install_manifests = [
            Identity("calico"), Identity("calico", "apiserver"), Identity("nginx-ingress-controller"),
            Identity("kubernetes-dashboard"), Identity("local-path-provisioner")
        ]
        for id_ in expected_install_manifests:
            self.assertTrue(builtin.is_manifest_installed(cluster, id_), f"Manifest {id_.name!r} is not to be installed")

        expected_pss_profiles = {
            'calico-apiserver': 'baseline',
            'ingress-nginx': 'privileged',
            'kubernetes-dashboard': 'baseline',
            'local-path-storage': 'privileged',
        }
        self.assertEqual(expected_pss_profiles, builtin.get_namespace_to_necessary_pss_profiles(cluster),
                         "Unexpected minimal PSS profiles for plugins' namespaces")

    def test_is_manifest_installed_custom_steps(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        plugin_section = inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})
        plugin_section['installation'] = {'procedures': [{'shell': 'whoami'}]}
        cluster = demo.new_cluster(inventory)

        self.assertFalse(builtin.is_manifest_installed(cluster, Identity("nginx-ingress-controller")),
                         f"Manifest 'nginx-ingress-controller' is unexpectedly to be installed")

        expected_pss_profiles = {
            'ingress-nginx': 'privileged',
        }
        self.assertEqual(expected_pss_profiles, builtin.get_namespace_to_necessary_pss_profiles(cluster),
                         "Unexpected minimal PSS profiles for plugins' namespaces")


if __name__ == '__main__':
    unittest.main()
