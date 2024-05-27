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
from test.unit.plugins import _AbstractManifestEnrichmentTest

from kubemarine import demo
from kubemarine.plugins.manifest import Manifest, Identity


class ManifestEnrichment(_AbstractManifestEnrichmentTest):
    def setUp(self):
        self.commonSetUp(Identity('kubernetes-dashboard'))
        # Requires kubernetes-dashboard v2.7.x
        self.k8s_latest = self.get_latest_k8s()

    def test_common_enrichment(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self.inventory(k8s_version)
                dashboard = inventory.setdefault('plugins', {}).setdefault('kubernetes-dashboard', {})
                dashboard.setdefault('installation', {})['registry'] = 'example.registry'
                dashboard['dashboard'] = {
                    'nodeSelector': {"kubernetes.io/os": "something-dashboard"},
                    'tolerations': [{"effect": "NoSchedule"}],
                }
                dashboard['metrics-scraper'] = {
                    'nodeSelector': {"kubernetes.io/os": "something-metrics-scraper"},
                    'tolerations': [{
                        "key": "node-role.kubernetes.io/control-plane",
                        "effect": "NoSchedule",
                    }],
                }
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                self._test_deployment_dashboard(manifest, k8s_version)
                self._test_deployment_metrics_scraper(manifest, k8s_version)

    def _test_deployment_dashboard(self, manifest: Manifest, k8s_version: str):
        expected_image = f"example.registry/kubernetesui/dashboard:{self.expected_image_tag(k8s_version, 'version')}"

        template_spec = self.get_obj(manifest, "Deployment_kubernetes-dashboard")['spec']['template']['spec']
        container = template_spec['containers'][0]
        self.assertEqual(expected_image, container['image'], "Unexpected dashboard image")
        self.assertEqual({"kubernetes.io/os": "something-dashboard"}, template_spec['nodeSelector'],
                         "Unexpected dashboard nodeSelector")
        self.assertEqual([{"effect": "NoSchedule"}],
                         template_spec.get('tolerations'),
                         "Unexpected dashboard tolerations")

    def _test_deployment_metrics_scraper(self, manifest: Manifest, k8s_version: str):
        expected_metrics_scrapper_image_version = self.expected_image_tag(k8s_version, 'metrics-scraper-version')
        expected_image = f"example.registry/kubernetesui/metrics-scraper:{expected_metrics_scrapper_image_version}"

        template_spec = self.get_obj(manifest, "Deployment_dashboard-metrics-scraper")['spec']['template']['spec']
        container = template_spec['containers'][0]
        self.assertEqual(expected_image, container['image'], "Unexpected metrics-scraper image")
        self.assertEqual({"kubernetes.io/os": "something-metrics-scraper"}, template_spec['nodeSelector'],
                         "Unexpected metrics-scraper nodeSelector")
        self.assertEqual([{"key": "node-role.kubernetes.io/control-plane",
                           "effect": "NoSchedule"}],
                         template_spec.get('tolerations'),
                         "Unexpected metrics-scraper tolerations")
        self.assertTrue('securityContext' in template_spec, "Unexpected securityContext spec")

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
                target_yaml: dict = self.get_obj(manifest, "Namespace_kubernetes-dashboard")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

    def test_all_images_contain_registry(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                num_images = self.check_all_images_contain_registry(self.inventory(k8s_version))
                self.assertEqual(2, num_images, f"Unexpected number of images found: {num_images}")


if __name__ == '__main__':
    unittest.main()
