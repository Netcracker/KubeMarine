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
from typing import List
from unittest import mock
from test.unit.plugins import _AbstractManifestEnrichmentTest
from test.unit import utils as test_utils

import yaml

from kubemarine import demo, plugins
from kubemarine.core import flow
from kubemarine.plugins.manifest import Manifest, Identity
from kubemarine.procedures import add_node, remove_node


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
        self.assertEqual('1430', data['veth_mtu'],
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
                    'tolerations': [{"key": 'something', "effect": "NoSchedule"}],
                })

                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml = self.get_obj(manifest, "Deployment_calico-typha")
                self.assertEqual(1, target_yaml['spec']['replicas'], "Unexpected number of typha replicas")

                template_spec = target_yaml['spec']['template']['spec']
                container = self._get_calico_typha_container(manifest)
                expected_image = f"example.registry/calico/typha:{self.expected_image_tag(k8s_version, 'version')}"
                self.assertEqual(expected_image, container['image'], "Unexpected calico-typha image")
                self.assertEqual({"kubernetes.io/os": "something"}, template_spec['nodeSelector'],
                                 "Unexpected calico-typha nodeSelector")

                default_tolerations = [
                    {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoSchedule'},
                    {'key': 'node.kubernetes.io/network-unavailable', 'effect': 'NoExecute'},
                    {'effect': 'NoExecute', 'operator': 'Exists'},
                    {'effect': 'NoSchedule', 'operator': 'Exists'},
                ]
                for toleration in default_tolerations:
                    self.assertEqual(1, sum(1 for t in template_spec['tolerations'] if t == toleration),
                                  "Default calico-typha toleration is not present")

                self.assertIn({"key": 'something', "effect": "NoSchedule"}, template_spec['tolerations'],
                              "Custom calico-typha toleration is not present")

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
                inventory.setdefault('rbac', {}).setdefault('pss', {}).setdefault('defaults', {})['enforce'] = profile
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml: dict = self.get_obj(manifest, "Namespace_calico-apiserver")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

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


def get_default_expect_config(typha_enabled: bool) -> dict:
    config = {
        'daemonsets': {'list': ['calico-node']},
        'deployments': {'list': ['calico-kube-controllers']},
        'pods': {'list': ['coredns', 'calico-kube-controllers', 'calico-node']},
    }
    if typha_enabled:
        config['deployments']['list'].append('calico-typha')
        config['pods']['list'].append('calico-typha')

    return config


class EnrichmentTest(unittest.TestCase):
    def test_default_typha_enrichment(self):
        for nodes in (1, 3, 4, 49, 50):
            with self.subTest(f"Kubernetes nodes: {nodes}"):
                inventory = self._inventory(nodes)
                cluster = demo.new_cluster(inventory)

                typha = cluster.inventory['plugins']['calico']['typha']

                expected_enabled = nodes > 3
                self.assertEqual(expected_enabled, typha['enabled'])

                expected_replicas = 0 if nodes <= 3 else 2 if 3 < nodes < 50 else 3
                self.assertEqual(expected_replicas, typha['replicas'])

    def test_replicas_default_typha_enabled(self):
        for nodes in (1, 2, 49, 50):
            with self.subTest(f"Kubernetes nodes: {nodes}"):
                inventory = self._inventory(nodes)
                inventory['plugins']['calico']['typha'] = {
                    'enabled': True
                }
                cluster = demo.new_cluster(inventory)

                typha = cluster.inventory['plugins']['calico']['typha']
                self.assertEqual(True, typha['enabled'])

                expected_replicas = 1 if nodes == 1 else 2 if 1 < nodes < 50 else 3
                self.assertEqual(expected_replicas, typha['replicas'])

    def test_expect_typha_default(self):
        for nodes in (3, 4):
            with self.subTest(f"Kubernetes nodes: {nodes}"):
                inventory = self._inventory(nodes)
                cluster = demo.new_cluster(inventory)

                expected_expect_step = get_default_expect_config(nodes > 3)

                steps = cluster.inventory['plugins']['calico']['installation']['procedures']
                actual_expect_steps = [step['expect'] for step in steps if 'expect' in step]
                self.assertEqual([expected_expect_step, expected_expect_step], actual_expect_steps,
                                 "Unexpected expect procedures")

    @staticmethod
    def _inventory(nodes: int) -> dict:
        scheme = {'control_plane': [], 'worker': []}
        for i in range(nodes):
            scheme['control_plane'].append(f'control-plane-{i + 1}')
            scheme['worker'].append(f'control-plane-{i + 1}')

        inventory = demo.generate_inventory(**scheme)
        inventory.setdefault('plugins', {})['calico'] = {
            'install': True,
        }

        return inventory


class RedeployIfNeeded(unittest.TestCase):
    def prepare_context(self, procedure: str):
        # pylint: disable=attribute-defined-outside-init
        task = 'deploy.plugins' if procedure == 'add_node' else 'update.plugins'
        self.context = demo.create_silent_context(['fake_path.yaml', '--tasks', task], procedure=procedure)
        self.action = add_node.AddNodeAction() if procedure == 'add_node' else remove_node.RemoveNodeAction()

    def prepare_inventory(self, scheme: dict, procedure: str, changed_node_name: str):
        # pylint: disable=attribute-defined-outside-init
        self.inventory = demo.generate_inventory(**scheme)
        self.inventory.setdefault('plugins', {})['calico'] = {
            'install': True,
            'typha': {}
        }

        changed_node_idx = next(i for i, node in enumerate(self.inventory['nodes'])
                                if node['name'] == changed_node_name)
        changed_node = (self.inventory['nodes'].pop(changed_node_idx) if procedure == 'add_node'
                        else self.inventory['nodes'][changed_node_idx])
        self.procedure_inventory = demo.generate_procedure_inventory(procedure)
        self.procedure_inventory['nodes'] = [changed_node]

    def _run_and_check(self, called: bool) -> demo.FakeResources:
        nodes_context = demo.generate_nodes_context(
            self.inventory, procedure_inventory=self.procedure_inventory, context=self.context)
        resources = test_utils.FakeResources(self.context, self.inventory,
                                             procedure_inventory=self.procedure_inventory, nodes_context=nodes_context)
        with mock.patch.object(plugins, plugins.install_plugin.__name__) as run:
            flow.run_actions(resources, [self.action])
            actual_called = any(call_args[0][1] == 'calico' for call_args in run.call_args_list)
            self.assertEqual(called, actual_called,
                             f"Re-install of 'calico' was {'not' if called else 'unexpectedly'} run")

        return resources

    @staticmethod
    def get_actual_step_configs(inventory: dict, procedure: str) -> List[dict]:
        steps = inventory['plugins']['calico']['installation']['procedures']
        return [step[procedure] for step in steps if procedure in step]

    def test_add_fourth_kubernetes_node_redeploy_needed(self):
        for role in ('control-plane', 'worker'):
            for typha_disabled_redefined in (False, True):
                with self.subTest(f'Role: {role}, Typha disabled: {typha_disabled_redefined}'):
                    scheme = {'balancer': ['balancer-1'],
                              'control_plane': ['control-plane-1', 'control-plane-2'],
                              'worker': ['worker-1', 'worker-2']}
                    add_node_name = 'control-plane-2' if role == 'control-plane' else 'worker-2'
                    self.prepare_context('add_node')
                    self.prepare_inventory(scheme, 'add_node', add_node_name)
                    if typha_disabled_redefined:
                        self.inventory['plugins']['calico']['typha']['enabled'] = False

                    res = self._run_and_check(not typha_disabled_redefined)

                    expected_expect_step = get_default_expect_config(not typha_disabled_redefined)

                    typha_enabled = res.working_inventory['plugins']['calico']['typha']['enabled']
                    self.assertEqual(not typha_disabled_redefined, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

                    actual_expect_steps = self.get_actual_step_configs(res.working_inventory, 'expect')
                    self.assertEqual([expected_expect_step, expected_expect_step], actual_expect_steps)

                    typha_enabled = res.finalized_inventory['plugins']['calico']['typha']['enabled']
                    self.assertEqual(not typha_disabled_redefined, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

                    actual_expect_steps = self.get_actual_step_configs(res.finalized_inventory, 'expect')
                    self.assertEqual([expected_expect_step, expected_expect_step], actual_expect_steps)

                    typha_enabled = res.inventory()['plugins']['calico']['typha'].get('enabled')
                    expected_enabled = None if not typha_disabled_redefined else False
                    self.assertEqual(expected_enabled, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

    def test_remove_fourth_kubernetes_node_redeploy_not_needed(self):
        for role in ('control-plane', 'worker'):
            for typha_enabled_redefined in (False, True):
                with self.subTest(f'Role: {role}, Typha enabled: {typha_enabled_redefined}'):
                    scheme = {'balancer': ['balancer-1'],
                              'control_plane': ['control-plane-1', 'control-plane-2'],
                              'worker': ['worker-1', 'worker-2']}
                    remove_node_name = 'control-plane-2' if role == 'control-plane' else 'worker-2'
                    self.prepare_context('remove_node')
                    self.prepare_inventory(scheme, 'remove_node', remove_node_name)
                    if typha_enabled_redefined:
                        self.inventory['plugins']['calico']['typha']['enabled'] = True

                    res = self._run_and_check(False)

                    expected_expect_step = get_default_expect_config(True)

                    typha_enabled = res.working_inventory['plugins']['calico']['typha']['enabled']
                    self.assertEqual(True, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

                    actual_expect_steps = self.get_actual_step_configs(res.working_inventory, 'expect')
                    self.assertEqual([expected_expect_step, expected_expect_step], actual_expect_steps)

                    typha_enabled = res.finalized_inventory['plugins']['calico']['typha']['enabled']
                    self.assertEqual(True, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

                    actual_expect_steps = self.get_actual_step_configs(res.finalized_inventory, 'expect')
                    self.assertEqual([expected_expect_step, expected_expect_step], actual_expect_steps)

                    typha_enabled = res.inventory()['plugins']['calico']['typha'].get('enabled')
                    self.assertEqual(True, typha_enabled,
                                     "Typha is not enabled in enriched inventory")

    def test_add_remove_balancer_redeploy_not_needed(self):
        # pylint: disable=attribute-defined-outside-init

        scheme = {'balancer': ['balancer-1', 'balancer-2'],
                  'control_plane': ['control-plane-1', 'control-plane-2'],
                  'worker': ['worker-1']}
        self.prepare_context('add_node')
        self.prepare_inventory(scheme, 'add_node', 'balancer-2')

        res = self._run_and_check(False)

        self.inventory = res.inventory()
        self.prepare_context('remove_node')

        self._run_and_check(False)

    def test_add_remove_second_kubernetes_node_redeploy_not_needed(self):
        # pylint: disable=attribute-defined-outside-init

        for role in ('control-plane', 'worker'):
            with self.subTest(f'Role: {role}'):
                scheme = {'balancer': 1, 'control_plane': ['control-plane-1'], 'worker': ['control-plane-1']}
                add_node_name = 'node-1'
                if role == 'control-plane':
                    scheme['control_plane'].append(add_node_name)
                else:
                    scheme['worker'].append(add_node_name)

                self.prepare_context('add_node')
                self.prepare_inventory(scheme, 'add_node', add_node_name)

                res = self._run_and_check(False)

                self.inventory = res.inventory()
                self.prepare_context('remove_node')

                self._run_and_check(False)

    def test_add_remove_second_kubernetes_node_typha_enabled_redeploy_needed(self):
        # pylint: disable=attribute-defined-outside-init

        for role in ('control-plane', 'worker'):
            for typha_replicas_redefined in (False, True):
                with self.subTest(f'Role: {role}, Typha replicas redefined: {typha_replicas_redefined}'):
                    scheme = {'balancer': 1, 'control_plane': ['control-plane-1'], 'worker': ['control-plane-1']}
                    add_node_name = 'node-1'
                    if role == 'control-plane':
                        scheme['control_plane'].append(add_node_name)
                    else:
                        scheme['worker'].append(add_node_name)

                    self.prepare_context('add_node')
                    self.prepare_inventory(scheme, 'add_node', add_node_name)
                    self.inventory['plugins']['calico']['typha']['enabled'] = True
                    if typha_replicas_redefined:
                        self.inventory['plugins']['calico']['typha']['replicas'] = 2

                    res = self._run_and_check(not typha_replicas_redefined)

                    self.inventory = res.inventory()
                    self.prepare_context('remove_node')

                    self._run_and_check(not typha_replicas_redefined)

    def test_add_remove_50th_kubernetes_node_redeploy_needed(self):
        # pylint: disable=attribute-defined-outside-init

        for role in ('control-plane', 'worker'):
            for typha_replicas_redefined in (False, True):
                with self.subTest(f'Role: {role}, Typha replicas redefined: {typha_replicas_redefined}'):
                    scheme = {'balancer': 1, 'control_plane': 25, 'worker': 25}
                    add_node_name = 'control-plane-25' if role == 'control-plane' else 'worker-25'
                    self.prepare_context('add_node')
                    self.prepare_inventory(scheme, 'add_node', add_node_name)
                    if typha_replicas_redefined:
                        self.inventory['plugins']['calico']['typha']['replicas'] = 2

                    res = self._run_and_check(not typha_replicas_redefined)

                    self.inventory = res.inventory()
                    self.prepare_context('remove_node')

                    self._run_and_check(not typha_replicas_redefined)

    def test_add_route_reflector_redeploy_needed(self):
        for fullmesh in (False, True):
            with self.subTest(f'fullmesh: {fullmesh}'):
                self.prepare_context('add_node')
                self.prepare_inventory(demo.MINIHA_KEEPALIVED, 'add_node', 'control-plane-3')
                self.inventory['plugins']['calico']['fullmesh'] = fullmesh

                self.procedure_inventory['nodes'][0].setdefault('labels', {})['route-reflector'] = True

                self._run_and_check(not fullmesh)

    def test_add_simple_node_fullmesh_disabled_redeploy_not_needed(self):
        self.prepare_context('add_node')
        self.prepare_inventory(demo.MINIHA_KEEPALIVED, 'add_node', 'control-plane-3')
        self.inventory['plugins']['calico']['fullmesh'] = False
        self._run_and_check(False)

    def test_add_route_reflector_custom_procedures_redeploy_not_needed(self):
        self.prepare_context('add_node')
        self.prepare_inventory(demo.MINIHA_KEEPALIVED, 'add_node', 'control-plane-3')
        self.inventory['plugins']['calico']['fullmesh'] = False
        self.inventory['plugins']['calico']['installation'] = {'procedures': [
            {'shell': 'whoami'}
        ]}

        self.procedure_inventory['nodes'][0].setdefault('labels', {})['route-reflector'] = True

        self._run_and_check(False)


if __name__ == '__main__':
    unittest.main()
