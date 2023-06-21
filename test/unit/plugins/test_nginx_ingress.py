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

from kubemarine import demo
from kubemarine.core import errors
from kubemarine.plugins.manifest import Manifest
from test.unit.plugins import _AbstractManifestEnrichmentTest


class EnrichmentValidation(unittest.TestCase):
    def install(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context()
        self.cert_renew = None
        self.cert_config = self.inventory.setdefault('plugins', {}).setdefault('nginx-ingress-controller', {})\
            .setdefault('controller', {}).setdefault('ssl', {}).setdefault('default-certificate', {})

    def cert_renew(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(procedure='cert_renew')
        self.cert_renew = {}
        self.cert_config = self.cert_renew.setdefault('nginx-ingress-controller', {})

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.cert_renew, context=self.context)

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
                with self.assertRaisesRegex(errors.FailException, r"Number of properties is greater than the maximum of 1\. Property names: \['data', 'paths']"):
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
        self.commonSetUp('nginx-ingress-controller')
        # Requires ingress-nginx v1.4.x
        self.k8s_latest = self.get_latest_k8s()
        # Requires ingress-nginx v1.2.x
        self.k8s_1_24_x = self.get_latest_k8s("v1.24")

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
                    }
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
            "proxy-set-headers": "ingress-nginx/custom-headers"
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
        self.assertIn('--watch-ingress-without-class=true', args, "Required arg not found")
        self.assertIn('--enable-ssl-passthrough', args, "Required arg not found")
        self.assertIn('--default-ssl-certificate=kube-system/default-ingress-cert', args, "Required arg not found ")

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
                rbac = inventory.setdefault('rbac', {})
                rbac['admission'] = 'pss'
                rbac.setdefault('pss', {}).setdefault('defaults', {})['enforce'] = profile
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml: dict = self.get_obj(manifest, "Namespace_ingress-nginx")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

    def test_webhook_resources_difference(self):
        for k8s_version, expected_num_resources in (
            (self.k8s_1_24_x, 0),
            (self.k8s_latest, 9)
        ):
            with self.subTest(k8s_version):
                cluster = demo.new_cluster(self.inventory(k8s_version))
                manifest = self.enrich_yaml(cluster)
                webhook_resources = 0
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

    def test_v1_2_x_controller_container_difference(self):
        for k8s_version, presence_checker in (
            (self.k8s_1_24_x, self.assertFalse),
            (self.k8s_latest, self.assertTrue)
        ):
            with self.subTest(k8s_version):
                cluster = demo.new_cluster(self.inventory(k8s_version))
                manifest = self.enrich_yaml(cluster)
                container = self.get_obj(manifest, "DaemonSet_ingress-nginx-controller")\
                    ['spec']['template']['spec']['containers'][0]
                args = container['args']
                presence_checker(any(arg.startswith('--validating-webhook=') for arg in args), "Unexpected arguments")
                presence_checker(any(arg.startswith('--validating-webhook-certificate=') for arg in args), "Unexpected arguments")
                presence_checker(any(arg.startswith('--validating-webhook-key=') for arg in args), "Unexpected arguments")
                presence_checker('volumeMounts' in container, "Unexpected volumeMounts spec")

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

    def test_v1_2_x_role_ingress_nginx_difference(self):
        for k8s_version, admission, presence_checker in (
            (self.k8s_1_24_x, 'psp', self.assertTrue),
            (self.k8s_1_24_x, 'pss', self.assertTrue), # This should probably be assertFalse
            (self.k8s_latest, 'pss', self.assertFalse)
        ):
            with self.subTest(f"{k8s_version}, {admission}"):
                inventory = self.inventory(k8s_version)
                inventory.setdefault('rbac', {})['admission'] = admission
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                rules = self.get_obj(manifest, "Role_ingress-nginx")['rules']
                presence_checker(any(("resourceNames", ["oob-host-network-psp"]) in rule.items() for rule in rules),
                                 "Rules list validation failed")

    def test_all_images_contain_registry(self):
        for k8s_version, expected_num_images in (
            (self.k8s_1_24_x, 1),
            (self.k8s_latest, 2)
        ):
            with self.subTest(k8s_version):
                num_images = self.check_all_images_contain_registry(self.inventory(k8s_version))
                self.assertEqual(expected_num_images, num_images, f"Unexpected number of images found: {num_images}")


if __name__ == '__main__':
    unittest.main()
