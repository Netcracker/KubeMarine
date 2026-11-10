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

import re
import unittest
from typing import Tuple
from unittest import mock

from kubemarine import demo, plugins
from kubemarine.plugins import headlamp


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.headlamp = self.inventory.setdefault('plugins', {}).setdefault('headlamp', {})
        self.headlamp['install'] = True

    def _apply(self) -> Tuple[str, str, str]:
        cluster = demo.new_cluster(self.inventory)
        alpine_version = cluster.inventory['plugins']['headlamp']['debugImage'].split(':')[-1]
        with mock.patch.object(plugins, plugins.apply_helm.__name__) as apply_helm:
            headlamp.apply_headlamp_chart(cluster)
        values = apply_helm.call_args.kwargs['config']['values']
        self.assertEqual(values['config']['nodeShellImage'], values['config']['podDebugImage'])
        return values['image']['registry'], values['config']['nodeShellImage'], alpine_version

    def test_default_registries(self):
        registry, debug_image, alpine_version = self._apply()
        self.assertEqual('ghcr.io', registry)
        self.assertEqual(f'library/alpine:{alpine_version}', debug_image)

    def test_plugin_defaults_registry(self):
        self.inventory['plugin_defaults'] = {'installation': {'registry': 'defaults.registry'}}
        registry, debug_image, alpine_version = self._apply()
        self.assertEqual('defaults.registry', registry)
        self.assertEqual(f'defaults.registry/library/alpine:{alpine_version}', debug_image)

    def test_plugin_registry(self):
        self.inventory['plugin_defaults'] = {'installation': {'registry': 'defaults.registry'}}
        self.headlamp['installation'] = {'registry': 'plugin.registry'}
        registry, debug_image, alpine_version = self._apply()
        self.assertEqual('plugin.registry', registry)
        self.assertEqual(f'plugin.registry/library/alpine:{alpine_version}', debug_image)

    def test_specific_registries(self):
        self.headlamp['installation'] = {'registry': 'plugin.registry'}
        self.headlamp['headlampRegistry'] = 'headlamp.registry'
        registry, debug_image, alpine_version = self._apply()
        self.assertEqual('headlamp.registry', registry)
        self.assertEqual(f'plugin.registry/library/alpine:{alpine_version}', debug_image)

        del self.headlamp['headlampRegistry']
        self.headlamp['debugRegistry'] = 'debug.registry'
        registry, debug_image, alpine_version = self._apply()
        self.assertEqual('plugin.registry', registry)
        self.assertEqual(f'debug.registry/library/alpine:{alpine_version}', debug_image)


class HostnameTest(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['cluster_name'] = 'k8s.example.com'
        self.plugins = self.inventory.setdefault('plugins', {})
        self.headlamp = self.plugins.setdefault('headlamp', {})
        self.headlamp['install'] = True
        self.plugins['nginx-ingress-controller'] = {'install': True}
        self.plugins['envoy-gateway'] = {'install': True}

    def _apply(self) -> dict:
        cluster = demo.new_cluster(self.inventory)
        with mock.patch.object(plugins, plugins.apply_helm.__name__) as apply_helm:
            headlamp.apply_headlamp_chart(cluster)
        return apply_helm.call_args.kwargs['config']['values']

    def test_default_hostname(self):
        values = self._apply()
        self.assertEqual('dashboard.k8s.example.com', values['ingress']['hosts'][0]['host'])
        self.assertEqual(['dashboard.k8s.example.com'], values['ingress']['tls'][0]['hosts'])
        self.assertEqual(['dashboard.k8s.example.com'], values['httpRoute']['hostnames'])

    def test_same_hostname_with_dashboard(self):
        self.plugins['kubernetes-dashboard'] = {'install': True}
        with self.assertRaisesRegex(Exception, re.escape(
                headlamp.ERROR_SAME_HOSTNAME.format(hostname='dashboard.k8s.example.com'))):
            demo.new_cluster(self.inventory)

    def test_different_hostname_with_dashboard(self):
        self.plugins['kubernetes-dashboard'] = {'install': True}
        self.headlamp['hostname'] = 'headlamp.{{ cluster_name }}'
        values = self._apply()
        self.assertEqual(['headlamp.k8s.example.com'], values['httpRoute']['hostnames'])

    def test_same_hostname_dashboard_not_installed(self):
        self.plugins['kubernetes-dashboard'] = {'install': False}
        demo.new_cluster(self.inventory)

    def test_auth_proxy_backend(self):
        self.headlamp['values'] = {
            'ingress': {'hosts': [{
                'host': '{{ plugins.headlamp.hostname }}',
                'paths': [{'path': '/', 'type': 'Prefix',
                           'backend': {'service': {'name': 'keycloak-gatekeeper', 'port': {'number': 80}}}}],
            }]},
            'httpRoute': {'rules': [{
                'matches': [{'path': {'type': 'PathPrefix', 'value': '/'}}],
                'backendRefs': [{'name': 'keycloak-gatekeeper', 'port': 80}],
            }]},
        }
        values = self._apply()
        ingress_host = values['ingress']['hosts'][0]
        self.assertEqual('dashboard.k8s.example.com', ingress_host['host'])
        self.assertEqual('keycloak-gatekeeper', ingress_host['paths'][0]['backend']['service']['name'])
        self.assertEqual(['dashboard.k8s.example.com'], values['ingress']['tls'][0]['hosts'])
        self.assertEqual('nginx', values['ingress']['ingressClassName'])

        http_route = values['httpRoute']
        self.assertEqual('keycloak-gatekeeper', http_route['rules'][0]['backendRefs'][0]['name'])
        self.assertEqual(['dashboard.k8s.example.com'], http_route['hostnames'])
        self.assertEqual('default-external-gateway', http_route['parentRefs'][0]['name'])


if __name__ == '__main__':
    unittest.main()
