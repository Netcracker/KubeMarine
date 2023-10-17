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

import io
import unittest

import yaml

from kubemarine import demo
from kubemarine.plugins.manifest import Manifest, Identity
from test.unit.plugins import _AbstractManifestEnrichmentTest


class ManifestEnrichment(_AbstractManifestEnrichmentTest):
    def setUp(self):
        self.commonSetUp(Identity('calico'))
        # Requires calico v3.24.x
        self.k8s_latest = self.get_latest_k8s()

    def _enable_typha(self, k8s_version: str, enable: bool):
        inventory = self.inventory(k8s_version)
        inventory.setdefault('plugins', {}).setdefault('calico', {}).setdefault('typha', {})['enabled'] = enable
        return inventory

    def _inventory_custom_registry(self, k8s_version: str):
        inventory = self.inventory(k8s_version)
        calico = inventory.setdefault('plugins', {}).setdefault('calico', {})
        calico.setdefault('installation', {})['registry'] = 'example.registry'
        return inventory

    def test_common_enrichment(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self._inventory_custom_registry(k8s_version)
                calico = inventory['plugins']['calico']
                calico['kube-controllers'] = {
                    'nodeSelector': {"kubernetes.io/os": "something"},
                    'tolerations': [{"effect": "NoSchedule"}],
                }
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                self._test_common_calico_config(manifest)
                self._test_deployment_calico_kube_controllers(manifest, k8s_version)
                self._test_daemonset_calico_node(manifest, k8s_version)

    def _test_common_calico_config(self, manifest: Manifest):
        data = self.get_obj(manifest, "ConfigMap_calico-config")['data']
        self.assertEqual('1440', data['veth_mtu'],
                         "Unexpected veth_mtu configuration in calico-config ConfigMap")

    def _test_deployment_calico_kube_controllers(self, manifest: Manifest, k8s_version: str):
        expected_image = f"example.registry/calico/kube-controllers:{self.expected_image_tag(k8s_version, 'version')}"

        template_spec = self.get_obj(manifest, "Deployment_calico-kube-controllers")['spec']['template']['spec']
        container = template_spec['containers'][0]
        self.assertEqual(expected_image, container['image'], "Unexpected calico-kube-controllers image")
        self.assertEqual({"kubernetes.io/os": "something"}, template_spec['nodeSelector'],
                         "Unexpected calico-kube-controllers nodeSelector")
        self.assertIn({"effect": "NoSchedule"}, template_spec.get('tolerations'),
                      "Custom calico-kube-controllers toleration is not present")

    def _test_daemonset_calico_node(self, manifest: Manifest, k8s_version: str):
        template_spec = self.get_obj(manifest, "DaemonSet_calico-node")['spec']['template']['spec']
        init_containers = template_spec['initContainers']
        expected_image = f"example.registry/calico/cni:{self.expected_image_tag(k8s_version, 'version')}"
        for container_name in ['upgrade-ipam', 'install-cni']:
            self.assertTrue(
                any(1 for c in init_containers if c['name'] == container_name and c['image'] == expected_image),
                f"{container_name} init container with {expected_image} image is not found")

        expected_image = f"example.registry/calico/node:{self.expected_image_tag(k8s_version, 'version')}"
        calico_node = self._get_calico_node_container(manifest)
        self.assertEqual(expected_image, calico_node.get('image'), "Unexpected calico-node image")

        self.assertTrue(any(1 for c in init_containers if c['name'] == 'mount-bpffs' and c['image'] == expected_image),
                        f"mount-bpffs init container with {expected_image} image is not found")

    def _get_calico_node_container(self, manifest: Manifest):
        containers = self.get_obj(manifest, "DaemonSet_calico-node")['spec']['template']['spec']['containers']
        return next((c for c in containers if c['name'] == 'calico-node'), None)

    def test_calico_config_ipam(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for ip_version in ('ipv4', 'ipv6'):
                with self.subTest(f"{k8s_version}, {ip_version}"):
                    inventory = self.inventory(k8s_version)
                    if ip_version == 'ipv6':
                        inventory['nodes'][0]['internal_address'] = '::1'
                    cluster = demo.new_cluster(inventory)
                    manifest = self.enrich_yaml(cluster)
                    data = self.get_obj(manifest, "ConfigMap_calico-config")['data']
                    cni_network_config = yaml.safe_load(io.StringIO(data['cni_network_config']))
                    ipam = cni_network_config['plugins'][0]['ipam']
                    if ip_version == 'ipv6':
                        self.assertEqual('fd02::/48', ipam.get('ipv6_pools', [None])[0],
                                         "Unexpected ipam configuration of calico plugin in calico-config ConfigMap")
                    else:
                        self.assertEqual('10.128.0.0/14', ipam.get('ipv4_pools', [None])[0],
                                         "Unexpected ipam configuration of calico plugin in calico-config ConfigMap")

    def test_calico_config_typha(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for typha_enabled in (False, True):
                with self.subTest(f"{k8s_version}, typha: {typha_enabled}"):
                    cluster = demo.new_cluster(self._enable_typha(k8s_version, typha_enabled))
                    manifest = self.enrich_yaml(cluster)
                    data = self.get_obj(manifest, "ConfigMap_calico-config")['data']
                    expected_typha_service_name = 'calico-typha' if typha_enabled else 'none'
                    self.assertEqual(expected_typha_service_name, data['typha_service_name'],
                                     "Unexpected typha_service_name of calico-config ConfigMap")

    def test_exclude_typha_objects(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for typha_enabled, expected_num_resources in (
                    (False, 0),
                    (True, 4)
            ):
                with self.subTest(f"{k8s_version}, typha: {typha_enabled}"):
                    cluster = demo.new_cluster(self._enable_typha(k8s_version, typha_enabled))
                    manifest = self.enrich_yaml(cluster)
                    typha_resources = 0
                    for key in self.all_obj_keys(manifest):
                        if 'typha' in key:
                            typha_resources += 1
                    self.assertEqual(expected_num_resources, typha_resources,
                                     f"calico should have {expected_num_resources} typha resources")

    def test_calico_node_env(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for ip_version in ('ipv4', 'ipv6'):
                with self.subTest(f"{k8s_version}, {ip_version}"):
                    inventory = self.inventory(k8s_version)
                    if ip_version == 'ipv6':
                        inventory['nodes'][0]['internal_address'] = '::1'
                    calico = inventory.setdefault('plugins', {}).setdefault('calico', {})
                    calico['mode'] = 'vxlan'
                    cluster = demo.new_cluster(inventory)
                    self._test_calico_node_env_ipv(cluster, ip_version)

    def _test_calico_node_env_ipv(self, cluster: demo.FakeKubernetesCluster, ip_version: str):
        present = object()
        absent = object()
        # Only some variables are verified
        expected_env = [
            ('CLUSTER_TYPE', 'k8s,bgp'),
            ('IP_AUTODETECTION_METHOD', 'first-found'),
            ('CALICO_DISABLE_FILE_LOGGING', 'true'),
            ('FELIX_LOGSEVERITYSCREEN', 'info'),
            ('FELIX_USAGEREPORTINGENABLED', 'false'),
            ('FELIX_PROMETHEUSMETRICSPORT', '9091'),
            ('NODENAME', present),
            ('FELIX_IPINIPMTU', present),
        ]
        if ip_version == 'ipv4':
            expected_env.extend([
                ('IP', 'autodetect'),
                ('CALICO_IPV4POOL_IPIP', 'Never'),
                ('CALICO_IPV4POOL_VXLAN', 'Always'),
                ('CALICO_IPV4POOL_CIDR', '10.128.0.0/14'),
                ('CALICO_IPV6POOL_CIDR', absent),
                ('IP6', absent),
                ('IP6_AUTODETECTION_METHOD', absent),
                ('FELIX_IPV6SUPPORT', 'false'),
                ('CALICO_IPV6POOL_IPIP', absent),
                ('CALICO_IPV6POOL_VXLAN', absent),
            ])
        elif ip_version == 'ipv6':
            expected_env.extend([
                ('CALICO_ROUTER_ID', 'hash'),
                ('IP', 'none'),
                ('CALICO_IPV4POOL_IPIP', 'Never'),
                ('CALICO_IPV4POOL_VXLAN', 'Never'),
                ('CALICO_IPV4POOL_CIDR', '192.168.0.0/16'),
                ('CALICO_IPV6POOL_CIDR', 'fd02::/48'),
                ('IP6', 'autodetect'),
                ('IP6_AUTODETECTION_METHOD', 'first-found'),
                ('FELIX_IPV6SUPPORT', 'true'),
                ('CALICO_IPV6POOL_IPIP', 'Never'),
                ('CALICO_IPV6POOL_VXLAN', 'Always'),
            ])

        manifest = self.enrich_yaml(cluster)
        calico_node_env = self._get_calico_node_container(manifest)['env']
        name_to_value = {e['name']: e.get('valueFrom', e.get('value')) for e in calico_node_env}
        for expected_name, expected_value in expected_env:
            if expected_value is present:
                self.assertIn(expected_name, name_to_value,
                              f"Env variable {expected_name!r} should be present")
            elif expected_value is absent:
                self.assertNotIn(expected_name, name_to_value,
                              f"Env variable {expected_name!r} should be absent")
            else:
                self.assertEqual(expected_value, name_to_value.get(expected_name),
                                 f"Unexpected value for {expected_name!r} env variable")

    def test_calico_node_env_typha(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for typha_enabled in (False, True):
                with self.subTest(f"{k8s_version}, typha: {typha_enabled}"):
                    cluster = demo.new_cluster(self._enable_typha(k8s_version, typha_enabled))
                    manifest = self.enrich_yaml(cluster)
                    calico_node_env = self._get_calico_node_container(manifest)['env']
                    self.assertEqual(typha_enabled, any(1 for e in calico_node_env if e['name'] == 'FELIX_TYPHAK8SSERVICENAME'),
                                     "Presence of FELIX_TYPHAK8SSERVICENAME variable validation failed")

    def test_deployment_calico_typha(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self._enable_typha(k8s_version, True)
                calico = inventory['plugins']['calico']
                calico.setdefault('installation', {})['registry'] = 'example.registry'
                calico['typha'].update({
                    'nodeSelector': {"kubernetes.io/os": "something"},
                    'tolerations': [{"effect": "NoSchedule"}],
                })

                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml = self.get_obj(manifest, "Deployment_calico-typha")
                self.assertEqual(2, target_yaml['spec']['replicas'], "Unexpected number of typha replicas")

                template_spec = target_yaml['spec']['template']['spec']
                container = self._get_calico_typha_container(manifest)
                expected_image = f"example.registry/calico/typha:{self.expected_image_tag(k8s_version, 'version')}"
                self.assertEqual(expected_image, container['image'], "Unexpected calico-typha image")
                self.assertEqual({"kubernetes.io/os": "something"}, template_spec['nodeSelector'],
                                 "Unexpected calico-typha nodeSelector")
                self.assertEqual([{'key': 'CriticalAddonsOnly', 'operator': 'Exists'},
                                  {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                                  {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'},
                                  {"effect": "NoSchedule"}],
                                 template_spec['tolerations'],
                                 "Unexpected calico-typha tolerations")

                self._test_calico_typha_env(manifest)

    def _get_calico_typha_container(self, manifest: Manifest):
        target_yaml = self.get_obj(manifest, "Deployment_calico-typha")
        return target_yaml['spec']['template']['spec']['containers'][0]

    def _test_calico_typha_env(self, manifest: Manifest):
        calico_typha_env = self._get_calico_typha_container(manifest)['env']
        expected_env = [
            ('TYPHA_PROMETHEUSMETRICSENABLED', 'true'),
            ('TYPHA_PROMETHEUSMETRICSPORT', '9093'),
        ]
        name_to_value = {e['name']: e.get('valueFrom', e.get('value')) for e in calico_typha_env}
        for expected_name, expected_value in expected_env:
            self.assertEqual(expected_value, name_to_value.get(expected_name),
                             f"Unexpected value for {expected_name!r} env variable")

    def test_clusterrole_calico_kube_controllers(self):
        k8s_1_24_x = self.get_latest_k8s("v1.24")
        for k8s_version, admission, presence_checker in (
            (k8s_1_24_x, 'psp', self.assertTrue),
            (k8s_1_24_x, 'pss', self.assertFalse),
            (self.k8s_latest, 'pss', self.assertFalse)
        ):
            with self.subTest(f"{k8s_version}, {admission}"):
                inventory = self.inventory(k8s_version)
                inventory.setdefault('rbac', {})['admission'] = admission
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                rules = self.get_obj(manifest, "ClusterRole_calico-kube-controllers")['rules']
                presence_checker(any(("resourceNames", ["oob-anyuid-psp"]) in rule.items() for rule in rules),
                                 "Rules list validation failed")

    def test_clusterrole_calico_node(self):
        k8s_1_24_x = self.get_latest_k8s("v1.24")
        for k8s_version, admission, presence_checker in (
            (k8s_1_24_x, 'psp', self.assertTrue),
            (k8s_1_24_x, 'pss', self.assertFalse),
            (self.k8s_latest, 'pss', self.assertFalse)
        ):
            with self.subTest(f"{k8s_version}, {admission}"):
                inventory = self.inventory(k8s_version)
                inventory.setdefault('rbac', {})['admission'] = admission
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                rules = self.get_obj(manifest, "ClusterRole_calico-node")['rules']
                presence_checker(any(("resourceNames", ["oob-privileged-psp"]) in rule.items() for rule in rules),
                                 "Rules list validation failed")

    def test_all_images_contain_registry(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for typha_enabled, expected_num_images in (
                    (False, 3),
                    (True, 4),
            ):
                with self.subTest(f"{k8s_version}, typha: {typha_enabled}"):
                    inventory = self._enable_typha(k8s_version, typha_enabled)
                    num_images = self.check_all_images_contain_registry(inventory)
                    self.assertEqual(expected_num_images, num_images, f"Unexpected number of images found: {num_images}")

    def test_metrics_services(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            for typha_enabled in (False, True):
                with self.subTest(f"{k8s_version}, typha: {typha_enabled}"):
                    cluster = demo.new_cluster(self._enable_typha(k8s_version, typha_enabled))
                    manifest = self.enrich_yaml(cluster)
                    self.assertTrue(manifest.has_obj("Service_calico-metrics"),
                                    "calico should have calico-metrics Service")
                    self.assertTrue(manifest.has_obj("Service_calico-kube-controllers-metrics"),
                                    "calico should have calico-kube-controllers-metrics Service")
                    self.assertEqual(typha_enabled, manifest.has_obj('Service_calico-typha-metrics'),
                                     f"calico should{'not ' if not typha_enabled else ''} have calico-typha-metrics Service")


class APIServerManifestEnrichment(_AbstractManifestEnrichmentTest):
    def setUp(self):
        self.commonSetUp(Identity('calico', 'apiserver'))
        self.k8s_latest = self.get_latest_k8s()

    def _inventory_custom_registry(self, k8s_version: str):
        inventory = self.inventory(k8s_version)
        calico = inventory.setdefault('plugins', {}).setdefault('calico', {})
        calico.setdefault('installation', {})['registry'] = 'example.registry'
        return inventory

    def test_common_enrichment(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self._inventory_custom_registry(k8s_version)
                calico = inventory['plugins']['calico']
                calico['apiserver'] = {
                    'nodeSelector': {"kubernetes.io/os": "something"},
                    'tolerations': [{"effect": "NoSchedule"}],
                }
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                self._test_deployment_calico_apiserver(manifest, k8s_version)

    def _test_deployment_calico_apiserver(self, manifest: Manifest, k8s_version: str):
        expected_image = f"example.registry/calico/apiserver:{self.expected_image_tag(k8s_version, 'version')}"

        template_spec = self.get_obj(manifest, "Deployment_calico-apiserver")['spec']['template']['spec']
        container = template_spec['containers'][0]
        self.assertEqual(expected_image, container['image'], "Unexpected calico-apiserver image")
        self.assertEqual({'requests': {'cpu': '50m', 'memory': '100Mi'}, 'limits': {'cpu': '100m', 'memory': '200Mi'}},
                         container.get('resources'), "Unexpected calico-apiserver resources")
        self.assertEqual({"kubernetes.io/os": "something"}, template_spec['nodeSelector'],
                         "Unexpected calico-apiserver nodeSelector")
        self.assertIn({"effect": "NoSchedule"}, template_spec.get('tolerations'),
                      "Custom calico-apiserver toleration is not present")

        args = container['args']
        self.assertIn('--tls-cert-file=apiserver.local.config/certificates/tls.crt', args, "Required arg not found")
        self.assertIn('--tls-private-key-file=apiserver.local.config/certificates/tls.key', args, "Required arg not found")

    def test_pss_labels(self):
        default_pss_labels = {
            'pod-security.kubernetes.io/enforce': 'baseline',
            'pod-security.kubernetes.io/enforce-version': 'latest',
            'pod-security.kubernetes.io/audit': 'baseline',
            'pod-security.kubernetes.io/audit-version': 'latest',
            'pod-security.kubernetes.io/warn': 'baseline',
            'pod-security.kubernetes.io/warn-version': 'latest',
        }
        for profile, default_label_checker in (('baseline', self.assertNotIn), ('restricted', self.assertIn)):
            with self.subTest(profile):
                inventory = self.inventory(self.k8s_latest)
                rbac = inventory.setdefault('rbac', {})
                rbac['admission'] = 'pss'
                rbac.setdefault('pss', {}).setdefault('defaults', {})['enforce'] = profile
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml: dict = self.get_obj(manifest, "Namespace_calico-apiserver")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

    def test_clusterrole_calico_crds(self):
        k8s_1_24_x = self.get_latest_k8s("v1.24")
        for k8s_version, admission, presence_checker in (
            (k8s_1_24_x, 'psp', self.assertTrue),
            (k8s_1_24_x, 'pss', self.assertFalse),
            (self.k8s_latest, 'pss', self.assertFalse)
        ):
            with self.subTest(f"{k8s_version}, {admission}"):
                inventory = self.inventory(k8s_version)
                inventory.setdefault('rbac', {})['admission'] = admission
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                rules = self.get_obj(manifest, "ClusterRole_calico-crds")['rules']
                presence_checker(any(("resourceNames", ["oob-anyuid-psp"]) in rule.items() for rule in rules),
                                 "Rules list validation failed")

    def test_redefine_resources(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self.inventory(k8s_version)
                calico = inventory.setdefault('plugins', {}).setdefault('calico', {})
                calico['apiserver'] = {
                    'resources': {'requests': {'cpu': '100m'}},
                }
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                container = self.get_obj(manifest, "Deployment_calico-apiserver")['spec']['template']['spec']['containers'][0]
                self.assertEqual({'requests': {'cpu': '100m'}},
                    container['resources'], "Unexpected calico-apiserver resources")


if __name__ == '__main__':
    unittest.main()
