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
from kubemarine.core import static


class TestRegistryEnrichment(unittest.TestCase):
    def test_default_enrichment(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri']['containerRuntime'] = 'containerd'
        inventory = demo.new_cluster(inventory).inventory

        self.assertEqual('registry.k8s.io', inventory['services']['kubeadm']['imageRepository'])
        self.assertEqual('registry.k8s.io/coredns', inventory['services']['kubeadm']['dns']['imageRepository'])
        for plugin_name, plugin_params in inventory['plugins'].items():
            if plugin_name == 'nginx-ingress-controller':
                self.assertEqual('registry.k8s.io', plugin_params['installation']['registry'])
            else:
                self.assertIsNone(plugin_params['installation'].get('registry'))

        containerd_config = inventory['services']['cri']['containerdConfig']
        path = 'plugins."io.containerd.grpc.v1.cri"'
        kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
        pause_version = static.GLOBALS['compatibility_map']['software']['pause'][kubernetes_version]['version']
        self.assertEqual(f'registry.k8s.io/pause:{pause_version}', containerd_config[path]['sandbox_image'])

    def test_apply_custom_unified_registry(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri']['containerRuntime'] = 'containerd'
        inventory['registry'] = {
            'endpoints': ['https://example.registry:443'],
            'mirror_registry': 'example.registry:443',
            'thirdparties': 'https://example.com/thirdparties'
        }
        inventory = demo.new_cluster(inventory).inventory

        self.assertEqual('example.registry:443', inventory['services']['kubeadm']['imageRepository'])
        self.assertEqual('example.registry:443/coredns', inventory['services']['kubeadm']['dns']['imageRepository'])
        self.assertEqual('example.registry:443', inventory['plugin_defaults']['installation']['registry'])
        for plugin_name, plugin_params in inventory['plugins'].items():
            self.assertEqual('example.registry:443', plugin_params['installation']['registry'])

        containerd_config = inventory['services']['cri']['containerdConfig']
        path = 'plugins."io.containerd.grpc.v1.cri"'
        kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
        pause_version = static.GLOBALS['compatibility_map']['software']['pause'][kubernetes_version]['version']
        self.assertEqual(f'example.registry:443/pause:{pause_version}', containerd_config[path]['sandbox_image'])

        registry_section = f'{path}.registry.mirrors."example.registry:443"'
        self.assertEqual(['https://example.registry:443'], containerd_config[registry_section]['endpoint'])

        for destination, config in inventory['services']['thirdparties'].items():
            if destination != '/usr/bin/etcdctl':
                self.assertIn('https://example.com/thirdparties/', config['source'])

    def test_plugin_defaults_custom_registry(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('plugin_defaults', {}).setdefault('installation', {})['registry'] = 'example.registry:443'
        inventory = demo.new_cluster(inventory).inventory

        for plugin_name, plugin_params in inventory['plugins'].items():
            self.assertEqual('example.registry:443', plugin_params['installation']['registry'])

    def test_custom_plugin_defaults_has_priority_over_unified_registry(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['registry'] = {
            'endpoints': ['https://example.registry:443'],
            'mirror_registry': 'example.registry:443',
        }
        inventory.setdefault('plugin_defaults', {}).setdefault('installation', {})['registry'] = 'example2.registry:443'
        inventory = demo.new_cluster(inventory).inventory

        for plugin_name, plugin_params in inventory['plugins'].items():
            self.assertEqual('example2.registry:443', plugin_params['installation']['registry'])

    def test_plugin_defaults_custom_registry_plugins_other_custom_registry(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory.setdefault('plugin_defaults', {}).setdefault('installation', {})['registry'] = 'example.registry:443'
        inventory['plugins'] = {
            'calico': {'installation': {'registry': 'example2.registry:443'}},
            'nginx-ingress-controller': {'installation': {'registry': 'example2.registry:443'}},
        }
        inventory = demo.new_cluster(inventory).inventory

        for plugin_name, plugin_params in inventory['plugins'].items():
            if plugin_name in ('calico', 'nginx-ingress-controller'):
                self.assertEqual('example2.registry:443', plugin_params['installation']['registry'])
            else:
                self.assertEqual('example.registry:443', plugin_params['installation']['registry'])

    def test_kubeadm_custom_image_repository(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri']['containerRuntime'] = 'containerd'
        inventory['services'].setdefault('kubeadm', {})['imageRepository'] = 'example.registry:443'
        inventory = demo.new_cluster(inventory).inventory

        self.assertEqual('example.registry:443/coredns', inventory['services']['kubeadm']['dns']['imageRepository'])

        containerd_config = inventory['services']['cri']['containerdConfig']
        path = 'plugins."io.containerd.grpc.v1.cri"'
        kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
        pause_version = static.GLOBALS['compatibility_map']['software']['pause'][kubernetes_version]['version']
        self.assertEqual(f'example.registry:443/pause:{pause_version}', containerd_config[path]['sandbox_image'])

    def test_kubeadm_custom_image_repository_dns_other_custom_image_repository(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['cri']['containerRuntime'] = 'containerd'
        inventory['services']['kubeadm'] = {
            'imageRepository': 'example.registry:443',
            'dns': {'imageRepository': 'example2.registry:443/coredns'}
        }
        inventory = demo.new_cluster(inventory).inventory

        self.assertEqual('example2.registry:443/coredns', inventory['services']['kubeadm']['dns']['imageRepository'])


if __name__ == '__main__':
    unittest.main()
