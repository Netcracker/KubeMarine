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
import re
import unittest
from unittest import mock
from test.unit.plugins import _AbstractManifestEnrichmentTest

from kubemarine import demo, plugins
from kubemarine.core import errors, flow
from kubemarine.plugins.manifest import Manifest, Identity
from kubemarine.procedures import add_node, remove_node


class EnrichmentValidation(unittest.TestCase):
    def install(self):
        # pylint: disable=attribute-defined-outside-init

        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context()
        self.procedure_inventory = None
        self.cert_config = self.inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})\
            .setdefault('controller', {}).setdefault('ssl', {}).setdefault('default-certificate', {})

    def cert_renew(self):
        # pylint: disable=attribute-defined-outside-init

        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(['fake.yaml'], procedure='cert_renew')
        self.procedure_inventory = demo.generate_procedure_inventory('cert_renew')
        self.cert_config = self.procedure_inventory.setdefault('nginx-ingress-controller', {})

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.procedure_inventory, context=self.context)

    def test_cert_both_data_paths_not_specified(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['unexpected_prop'] = 'value'
                with self.assertRaisesRegex(errors.FailException, r"'unexpected_prop' was unexpected"):
                    self._new_cluster()

    def test_cert_both_data_paths_specified(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'cert': 'c', 'key': 'k'}
                self.cert_config['paths'] = {'cert': 'c', 'key': 'k'}
                with self.assertRaisesRegex(
                        errors.FailException,
                        re.escape("Number of properties is greater than the maximum of 1. Property names: ['data', 'paths']")):
                    self._new_cluster()

    def test_cert_missed_cert(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'key': 'k'}
                with self.assertRaisesRegex(errors.FailException, r"'cert' is a required property"):
                    self._new_cluster()

    def test_cert_missed_key(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['paths'] = {'cert': 'c'}
                with self.assertRaisesRegex(errors.FailException, r"'key' is a required property"):
                    self._new_cluster()

    def test_cert_valid(self):
        for procedure in (self.install, self.cert_renew):
            with self.subTest(procedure.__name__):
                procedure()
                self.cert_config['data'] = {'cert': 'c', 'key': 'k'}
                self._new_cluster()


class ManifestEnrichment(_AbstractManifestEnrichmentTest):
    def setUp(self):
        self.commonSetUp(Identity('nginx-ingress-controller'))
        # Requires ingress-nginx >= v1.9.5
        self.k8s_latest = self.get_latest_k8s()
        # Requires ingress-nginx < v1.9.5
        self.k8s_1_28_x = self.get_latest_k8s("v1.28")
        # Requires ingress-nginx < v1.9.0
        self.k8s_1_25_x = self.get_latest_k8s("v1.25")

    def test_common_enrichment(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self.inventory(k8s_version)
                nginx = inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})
                nginx['config_map'] = {
                    'foo': 'bar'
                }
                nginx['custom_headers'] = {
                    'wheel': 'eggs'
                }
                nginx.setdefault('installation', {})['registry'] = 'example.registry'
                nginx['controller'] = {
                    'nodeSelector': {"kubernetes.io/os": "something"},
                    'tolerations': [{"effect": "NoSchedule"}],
                    'ssl': {
                        'enableSslPassthrough': True,
                        'default-certificate': {'data': {'cert': 'c', 'key': "k"}}
                    },
                    'args': [
                        "--disable-full-test",
                        "--disable-catch-all",
                    ]
                }
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                self._test_config_maps(manifest)
                self._test_controller(manifest, k8s_version)
                self._test_ingress_class(manifest)

    def _test_config_maps(self, manifest: Manifest):
        default_cm = self.get_obj(manifest, "ConfigMap_ingress-nginx-controller")['data']
        self.assertEqual({
            "allow-snippet-annotations": "true",
            "foo": "bar",
            "proxy-set-headers": "ingress-nginx/custom-headers",
            "use-proxy-protocol": "true"
        }, default_cm, "Unexpected ingress-nginx-controller ConfigMap content")

        custom_headers = self.get_obj(manifest, "ConfigMap_custom-headers")['data']
        self.assertEqual({'wheel': 'eggs'}, custom_headers, "Unexpected custom-headers ConfigMap content")

    def _test_controller(self, manifest: Manifest, k8s_version: str):
        template_spec = self.get_obj(manifest, "DaemonSet_ingress-nginx-controller")['spec']['template']['spec']
        container = template_spec['containers'][0]
        expected_image = f"example.registry/ingress-nginx/controller:{self.expected_image_tag(k8s_version, 'version')}"
        self.assertEqual(expected_image, container['image'], "Unexpected controller image")
        self.assertEqual({"kubernetes.io/os": "something"}, template_spec['nodeSelector'], "Unexpected controller nodeSelector")
        self.assertEqual([{"effect": "NoSchedule"}], template_spec.get('tolerations'), "Unexpected controller tolerations")

        args = container['args']
        self.assertFalse(any(arg.startswith('--publish-service=') for arg in args), "--publish-service should be absent")
        self.assertFalse(any(arg.startswith('--enable-metrics=') for arg in args), "--enable-metrics should be absent")
        self.assertIn('--watch-ingress-without-class=true', args, "Required arg not found")
        self.assertIn('--enable-ssl-passthrough', args, "Required arg not found")
        self.assertIn('--default-ssl-certificate=kube-system/default-ingress-cert', args, "Required arg not found")
        self.assertIn('--disable-full-test', args, "Required arg not found")
        self.assertIn('--disable-catch-all', args, "Required arg not found")
        self.assertTrue(any(arg.startswith('--validating-webhook=') for arg in args), "Required arg not found")
        self.assertTrue(any(arg.startswith('--validating-webhook-certificate=') for arg in args), "Required arg not found")
        self.assertTrue(any(arg.startswith('--validating-webhook-key=') for arg in args), "Required arg not found")

        self.assertEqual([80, 443, 10254, 8443],
                         [item['containerPort'] for item in container['ports']],
                         "Unexpected container ports")

    def _test_ingress_class(self, manifest: Manifest):
        target_yaml: dict = self.get_obj(manifest, "IngressClass_nginx")
        is_default_class = target_yaml['metadata'].get('annotations', {}).get('ingressclass.kubernetes.io/is-default-class')
        self.assertEqual('true', is_default_class, "Unexpected ingress class annotations")

    def test_pss_labels(self):
        default_pss_labels = {
            'pod-security.kubernetes.io/enforce': 'privileged',
            'pod-security.kubernetes.io/enforce-version': 'latest',
            'pod-security.kubernetes.io/audit': 'privileged',
            'pod-security.kubernetes.io/audit-version': 'latest',
            'pod-security.kubernetes.io/warn': 'privileged',
            'pod-security.kubernetes.io/warn-version': 'latest',
        }
        for profile, default_label_checker in (('baseline', self.assertIn), ('privileged', self.assertNotIn)):
            with self.subTest(profile):
                inventory = self.inventory(self.k8s_latest)
                inventory.setdefault('rbac', {}).setdefault('pss', {}).setdefault('defaults', {})['enforce'] = profile
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml: dict = self.get_obj(manifest, "Namespace_ingress-nginx")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

    def test_webhook_resources_difference(self):
        for k8s_version, expected_num_resources in (
            (self.k8s_1_25_x, 9),
            (self.k8s_1_28_x, 10),
            (self.k8s_latest, 9)
        ):
            with self.subTest(k8s_version):
                cluster = demo.new_cluster(self.inventory(k8s_version))
                manifest = self.enrich_yaml(cluster)
                webhook_resources = 0

                # Check if nginx-ingress-controller version is v1.9.5 or v1.9.6 before counting webhook resources
                nginx_version = self.get_obj(manifest, "DaemonSet_ingress-nginx-controller")\
                    ['spec']['template']['spec']['containers'][0]['image']
                if "v1.9.5" in nginx_version or "v1.9.6" in nginx_version or "v1.10.1" in nginx_version:
                    expected_num_resources = 9  # Adjust expected number for v1.9.5 and v1.9.6

                for key in self.all_obj_keys(manifest):
                    if 'admission' in key:
                        webhook_resources += 1

                self.assertEqual(expected_num_resources, webhook_resources,
                                 f"ingress-nginx for {k8s_version} should have {expected_num_resources} webhook resources")

    def test_service_ipv6(self):
        inventory = self.inventory(self.k8s_latest)
        inventory['nodes'][0]['internal_address'] = '2001::1'
        cluster = demo.new_cluster(inventory)
        manifest = self.enrich_yaml(cluster)
        data = self.get_obj(manifest, "Service_ingress-nginx-controller")
        self.assertEqual(['IPv6'], data['spec']['ipFamilies'],
                        f"ingress-nginx enrichment error for IPv6 family")

    def test_enrich_webhook_resources(self):
        inventory = self.inventory(self.k8s_latest)
        nginx = inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})
        nginx.setdefault('installation', {})['registry'] = 'example.registry'
        cluster = demo.new_cluster(inventory)

        manifest = self.enrich_yaml(cluster)
        expected_webhook_image_tag = self.expected_image_tag(self.k8s_latest, 'webhook-version')
        expected_image = f"example.registry/ingress-nginx/kube-webhook-certgen:{expected_webhook_image_tag}"

        container_create = self.get_obj(manifest, "Job_ingress-nginx-admission-create")\
            ['spec']['template']['spec']['containers'][0]
        self.assertEqual(expected_image, container_create['image'], "Unexpected create job image")
        container_patch = self.get_obj(manifest, "Job_ingress-nginx-admission-patch")\
            ['spec']['template']['spec']['containers'][0]
        self.assertEqual(expected_image, container_patch['image'], "Unexpected patch job image")

    def test_all_images_contain_registry(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                num_images = self.check_all_images_contain_registry(self.inventory(k8s_version))
                self.assertEqual(2, num_images, f"Unexpected number of images found: {num_images}")


class RedeployIfNeeded(unittest.TestCase):
    def test_add_remove_node_ingress_nginx_disabled(self):
        # Don't need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if nginx-ingress-controller plugin is disabled at all

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['plugins'] = {
            'nginx-ingress-controller': {
                'install': False
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_ingress_no_balancers_in_cluster(self):
        # Don't need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if no balancers are presented (in current cluster and as part of add/remove configuration)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=0)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = inventory['nodes'][0]
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_node_not_balancer_added(self):
        # Don't need to redeploy nginx-ingress-controller for add_node procedure,
        # if we don't add balancers
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        add_node = next(filter(lambda node: 'balancer' not in node['roles'], inventory['nodes']))
        inventory['nodes'].remove(add_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_remove_node_not_balancer_removed(self):
        # Don't need to redeploy nginx-ingress-controller for remove_node procedure,
        # if we don't remove balancers
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = next(filter(lambda node: 'balancer' not in node['roles'], inventory['nodes']))
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_node_not_first_balancer_added(self):
        # Don't need to redeploy nginx-ingress-controller for add_node procedure,
        # if we add not first balancer
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=2)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        add_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['nodes'].remove(add_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_remove_node_not_last_balancer_removed(self):
        # Don't need to redeploy nginx-ingress-controller for remove_node procedure,
        # if we remove the last balancer from cluster
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=2)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_node_fist_balancer_added(self):
        # Need to redeploy nginx-ingress-controller for add_node procedure,
        # if we add the first balancer
        # and changed parameters are not overriden by user
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        add_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['nodes'].remove(add_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_remove_node_last_balancer_removed(self):
        # Need to redeploy nginx-ingress-controller for remove_node procedure,
        # if we remove the last balancer
        # and changed parameters are not overriden by user
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_use_proxy_protocol_overriden(self):
        # Need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # and user overrides only use-proxy-protocol (ingress ports should already be changed)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['plugins'] = {
            'nginx-ingress-controller': {
                'config_map': {
                    'use-proxy-protocol': 'true'
                }
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_http_target_port_overriden(self):
        # Need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # and user overrides only one http port (use-proxy-protocol and https port should already be changed)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['services'] = {
            'loadbalancer': {
                'target_ports': {
                    'http': 80
                }
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_https_target_port_overriden(self):
        # Need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # and user overrides only one https port (use-proxy-protocol and http port should already be changed)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['services'] = {
            'loadbalancer': {
                'target_ports': {
                    'https': 443
                }
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_use_proxy_protocol_and_target_ports_overriden(self):
        # Don't need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # but user overrides use-proxy protocol and target http/https port (constant configuration)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['plugins'] = {
            'nginx-ingress-controller': {
                'config_map': {
                    'use-proxy-protocol': 'true'
                }
            }
        }
        inventory['services'] = {
            'loadbalancer': {
                'target_ports': {
                    'http': 80,
                    'https': 443
                }
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_host_ports_overriden(self):
        # Need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # and user overrides ds ports directly, that has more priority (use-proxy-protocol should already be changed)

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['plugins'] = {
            'nginx-ingress-controller': {
                'ports': [{
                    "name": "http",
                    "containerPort": 80,
                    "protocol": "TCP"
                },{
                    "name": "http",
                    "containerPort": 443,
                    "protocol": "TCP"
                }]
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(True, inventory, procedure_inventory=procedure_inventory, context=context)

    def test_add_remove_node_use_proxy_protocol_and_host_ports_overriden(self):
        # Don't need to redeploy nginx-ingress-controller for add/remove node procedure,
        # if we add the first/ remove the last balancer
        # and user overrides use-proxy-protocol and ds ports directly, that has more priority

        # Remove mode
        inventory = demo.generate_inventory(control_plane=2, worker=['control-plane-1', 'control-plane-2'], balancer=1)
        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        add_remove_node = next(filter(lambda node: 'balancer' in node['roles'], inventory['nodes']))
        inventory['plugins'] = {
            'nginx-ingress-controller': {
                'config_map': {
                    'use-proxy-protocol': 'true'
                },
                'ports': [{
                    "name": "http",
                    "containerPort": 80,
                    "protocol": "TCP"
                },{
                    "name": "http",
                    "containerPort": 443,
                    "protocol": "TCP"
                }]
            }
        }
        procedure_inventory = demo.generate_procedure_inventory('remove_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

        # Add node
        context = demo.create_silent_context(['fake.yaml'], procedure='add_node')
        inventory['nodes'].remove(add_remove_node)
        procedure_inventory = demo.generate_procedure_inventory('add_node')
        procedure_inventory['nodes'] = [add_remove_node]
        self._redeploy_ingress_nginx_is_needed(False, inventory, procedure_inventory=procedure_inventory, context=context)

    def _redeploy_ingress_nginx_is_needed(self, needed: bool,
                                          inventory: dict, procedure_inventory: dict, context: dict):
        procedure = context['initial_procedure']
        context['execution_arguments']['tasks'] = 'deploy.plugins' if procedure == 'add_node' else 'update.plugins'
        action = add_node.AddNodeAction() if procedure == 'add_node' else remove_node.RemoveNodeAction()
        resources = demo.new_resources(inventory, procedure_inventory=procedure_inventory, context=context)
        with mock.patch.object(plugins, plugins.install_plugin.__name__) as run:
            flow.run_actions(resources, [action])
            actual_called = any(call_args[0][1] == 'nginx-ingress-controller' for call_args in run.call_args_list)
            self.assertEqual(needed, actual_called,
                             f"Re-install of 'nginx-ingress-controller' was {'not' if needed else 'unexpectedly'} run")


if __name__ == '__main__':
    unittest.main()
