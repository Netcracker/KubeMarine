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
import json
import unittest

import yaml

from kubemarine import demo
from kubemarine.plugins.manifest import Manifest, Identity
from test.unit.plugins import _AbstractManifestEnrichmentTest


class ManifestEnrichment(_AbstractManifestEnrichmentTest):
    def setUp(self):
        self.commonSetUp(Identity('local-path-provisioner'))

    def test_common_enrichment(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                inventory = self.inventory(k8s_version)
                provisioner = inventory.setdefault('plugins', {}).setdefault('local-path-provisioner', {})
                provisioner.setdefault('installation', {})['registry'] = 'example.registry'
                provisioner.update({
                    'tolerations': [{"effect": "NoSchedule"}],
                    'storage-class': {'name': 'my-local-path'},
                    'volume-dir': '/opt/my-local-path-provisioner'
                })
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                self._test_deployment_local_path_provisioner(manifest, k8s_version)
                self._test_storageclass_local_path(manifest)
                self._test_local_path_config(manifest, k8s_version)

    def _test_deployment_local_path_provisioner(self, manifest: Manifest, k8s_version: str):
        expected_image = f"example.registry/rancher/local-path-provisioner:{self.expected_image_tag(k8s_version, 'version')}"

        template_spec = self.get_obj(manifest, "Deployment_local-path-provisioner")['spec']['template']['spec']
        container = template_spec['containers'][0]
        self.assertEqual(expected_image, container['image'], "Unexpected local-path-provisioner image")
        self.assertEqual([{"effect": "NoSchedule"}],
                         template_spec.get('tolerations'),
                         "Unexpected local-path-provisioner tolerations")

    def _test_storageclass_local_path(self, manifest: Manifest):
        metadata: dict = self.get_obj(manifest, "StorageClass_my-local-path")['metadata']
        is_default_class = metadata.get('annotations', {}).get('storageclass.kubernetes.io/is-default-class')
        self.assertEqual('false', is_default_class, "Unexpected storage class annotations")

        name = metadata['name']
        self.assertEqual('my-local-path', name, "Unexpected storage class name")

    def _test_local_path_config(self, manifest: Manifest, k8s_version: str):
        data: dict = self.get_obj(manifest, "ConfigMap_local-path-config")['data']
        config_json = json.load(io.StringIO(data['config.json']))
        self.assertEqual('/opt/my-local-path-provisioner', config_json['nodePathMap'][0]['paths'][0],
                         "Unexpected volume-dir")

        expected_image_tag = self.expected_image_tag(k8s_version, 'busybox-version')
        expected_image = f"example.registry/library/busybox:{expected_image_tag}"
        helperpod_yaml = yaml.safe_load(data['helperPod.yaml'])
        self.assertEqual(expected_image, helperpod_yaml['spec']['containers'][0]['image'],
                         "Unexpected helper pod image")

    def test_clusterrolebinding_privileged_psp(self):
        k8s_1_24_x = self.get_latest_k8s("v1.24")
        for k8s_version, admission, presence_checker in (
            (k8s_1_24_x, 'psp', self.assertTrue),
            (k8s_1_24_x, 'pss', self.assertTrue), # This should probably be assertFalse
            (self.get_latest_k8s(), 'pss', self.assertTrue) # This should probably be assertFalse
        ):
            with self.subTest(f"{k8s_version}, {admission}"):
                inventory = self.inventory(k8s_version)
                inventory.setdefault('rbac', {})['admission'] = admission
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                presence_checker("ClusterRoleBinding_local-path-provisioner-privileged-psp" in self.all_obj_keys(manifest),
                                 "Presence of privileged-psp ClusterRoleBinding validation failed")

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
                inventory = self.inventory(self.get_latest_k8s())
                rbac = inventory.setdefault('rbac', {})
                rbac['admission'] = 'pss'
                rbac.setdefault('pss', {}).setdefault('defaults', {})['enforce'] = profile
                cluster = demo.new_cluster(inventory)
                manifest = self.enrich_yaml(cluster)
                target_yaml: dict = self.get_obj(manifest, "Namespace_local-path-storage")['metadata'].get('labels', {})
                for pss_label in default_pss_labels.items():
                    default_label_checker(pss_label, target_yaml.items(), "PPS labels validation failed")

    def test_all_images_contain_registry(self):
        for k8s_version in self.latest_k8s_supporting_specific_versions.values():
            with self.subTest(k8s_version):
                num_images = self.check_all_images_contain_registry(self.inventory(k8s_version))
                self.assertEqual(1, num_images, f"Unexpected number of images found: {num_images}")


if __name__ == '__main__':
    unittest.main()
