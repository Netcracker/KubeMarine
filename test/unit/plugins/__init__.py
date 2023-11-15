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
from typing import Optional, List, Dict

from kubemarine import demo
from kubemarine.core import static, utils
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Manifest, Identity


class _AbstractManifestEnrichmentTest(unittest.TestCase):
    def commonSetUp(self, manifest_identity: Identity):
        self.manifest_identity = manifest_identity
        self.plugin_name = manifest_identity.plugin_name
        self.k8s_versions = list(static.GLOBALS['compatibility_map']['software']['kubeadm'].keys())
        self.k8s_versions.sort(key=utils.version_key)

        self.latest_k8s_supporting_specific_versions: Dict[str, str] = {}
        plugin_versions = list({plugin['version'] for k8s, plugin in self.compatibility_map().items()})
        for plugin_version in plugin_versions:
            latest_k8s = next(k8s for k8s in reversed(self.k8s_versions)
                              if self.compatibility_map()[k8s]['version'] == plugin_version)
            self.latest_k8s_supporting_specific_versions[plugin_version] = latest_k8s

    def compatibility_map(self) -> dict:
        return static.GLOBALS['compatibility_map']['software'][self.plugin_name]

    def expected_image_tag(self, k8s_version: str, image: str):
        return self.compatibility_map()[k8s_version].get(image)

    def get_latest_k8s(self, minor_k8s_version: Optional[str] = None) -> str:
        return next(k8s for k8s in reversed(self.k8s_versions)
                    if minor_k8s_version is None or utils.minor_version(k8s) == minor_k8s_version)

    def get_obj(self, manifest: Manifest, key: str):
        return manifest.get_obj(key, patch=False)

    def all_obj_keys(self, manifest: Manifest) -> List[str]:
        return manifest.all_obj_keys()

    def inventory(self, k8s_version):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version
        return inventory

    def enrich_yaml(self, cluster: demo.FakeKubernetesCluster) -> Manifest:
        # For regression testing with jinja templates, the following code can be used instead of builtin.apply_yaml
        # with mock.patch('kubemarine.plugins.apply_source') as apply_source:
        #     from kubemarine import plugins
        #     version = cluster.inventory['plugins'][self.plugin_name]['version']
        #     version = utils.minor_version(version)
        #     config = {
        #         "source": f"templates/plugins/<paste template filename>.yaml.j2"
        #     }
        #     plugins.apply_template(cluster, config)
        processor = builtin._get_manifest_processor(cluster.log, cluster.inventory, self.manifest_identity)
        return processor.enrich()

    def check_all_images_contain_registry(self, inventory: dict) -> int:
        nginx = inventory.setdefault('plugins', {}).setdefault(self.plugin_name, {})
        nginx.setdefault('installation', {})['registry'] = 'example.registry'
        cluster = demo.new_cluster(inventory)
        manifest = self.enrich_yaml(cluster)
        images = manifest.get_all_container_images()
        for image in images:
            self.assertTrue(image.startswith('example.registry/'),
                            f"{image} was not enriched with registry")

        return len(images)
