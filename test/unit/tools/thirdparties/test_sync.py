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
import re
import unittest
from contextlib import contextmanager
from copy import deepcopy
from typing import List, Dict, ContextManager
from unittest import mock

import yaml
from ruamel.yaml import CommentedMap

from kubemarine.core import utils, static
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Manifest, Processor, Identity
from scripts.thirdparties.src.software import thirdparties, plugins
from scripts.thirdparties.src.software.plugins import (
    ManifestResolver, ManifestsEnrichment,
    ERROR_UNEXPECTED_IMAGE, ERROR_SUSPICIOUS_ABA_VERSIONS
)
from scripts.thirdparties.src.tracker import (
    SummaryTracker, ERROR_PREVIOUS_MINOR
)
from test.unit import utils as test_utils
from test.unit.tools.thirdparties.stub import (
    FakeSynchronization, FakeInternalCompatibility, FakeKubernetesVersions,
    FAKE_CACHED_MANIFEST_RESOLVER, FakeManifest, NoneManifestsEnrichment, FakeUpgradeConfig
)


ORIGINAL_COMPATIBILITY_MAPS = {}

for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
    ORIGINAL_COMPATIBILITY_MAPS[config_filename] = static.load_compatibility_map(config_filename)


class SynchronizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.compatibility = FakeInternalCompatibility()
        self.kubernetes_versions = FakeKubernetesVersions()
        self.manifest_resolver = FAKE_CACHED_MANIFEST_RESOLVER
        self.manifests_enrichment = NoneManifestsEnrichment()
        self.upgrade_config = FakeUpgradeConfig()

    def test_clean_run_changes_nothing(self):
        self.run_sync()
        for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
            self.assertTrue(ORIGINAL_COMPATIBILITY_MAPS[config_filename] == self.compatibility.stored[config_filename],
                            f"{config_filename} was changed without any change in kubernetes_versions.yaml")

    def test_kubernetes_versions_add_minor_version(self):
        k8s_latest = self.k8s_versions()[-1]
        new_version = test_utils.increment_version(k8s_latest, minor=True)
        self.compatibility_map()[new_version] = deepcopy(self.compatibility_map()[k8s_latest])

        self.run_sync()
        self.assertIn(utils.minor_version(new_version), self.kubernetes_versions.stored['kubernetes_versions'])

    def test_kubernetes_versions_remove_minor_version(self):
        k8s_oldest = self.k8s_versions()[0]
        for k8s_version in self.k8s_versions():
            if utils.minor_version(k8s_version) == utils.minor_version(k8s_oldest):
                del self.compatibility_map()[k8s_version]

        self.run_sync()
        self.assertNotIn(utils.minor_version(k8s_oldest), self.kubernetes_versions.stored['kubernetes_versions'])

    def test_compatibility_mapping_add_new_versions(self):
        k8s_versions = self.k8s_versions()
        k8s_latest = k8s_versions[-1]
        k8s_intermediate = k8s_latest if len(k8s_versions) == 1 else k8s_versions[1]
        from_versions = [k8s_latest, k8s_intermediate]
        new_versions = list(from_versions)
        for i, ver in enumerate(new_versions):
            while ver in k8s_versions or ver in new_versions[:i]:
                new_versions[i] = ver = test_utils.increment_version(ver)

            self.compatibility_map()[ver] = deepcopy(self.compatibility_map()[from_versions[i]])

        tracker = self.run_sync()
        for i, ver in enumerate(new_versions):
            from_ver = from_versions[i]
            self._check_added_plugins(ver, from_ver)
            self._check_added_thirdparties(ver, from_ver)
            self._check_added_k8s_images(ver, from_ver)
            self._check_added_packages(ver, from_ver)

        requirements = tracker.get_changed_software_requirements()
        self.assertEqual(new_versions, list(requirements), "Unexpected Kubernetes versions were changed")
        expected_software = {'calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner',
                             'containerd', 'crictl'}
        for ver in new_versions:
            self.assertEqual(expected_software,
                             {name for name, _ in requirements[ver]},
                             "Unexpected software was changed")

    def _check_added_plugins(self, ver: str, from_ver: str):
        expected_mapping = {}
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            expected_mapping[plugin] = ORIGINAL_COMPATIBILITY_MAPS['plugins.yaml'][plugin][from_ver]

        self._check_added_plugins_by_mapping(ver, expected_mapping)

    def _check_added_plugins_by_mapping(self, ver: str, expected_mapping: dict):
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            software_mapping = self.compatibility.stored['plugins.yaml'][plugin]
            actual_mapping = software_mapping.get(ver, {})
            self.assertEqual(expected_mapping[plugin]['version'],
                             actual_mapping.get('version'),
                             f"Version for {plugin!r} and Kubernetes {ver} was not synced")
            self.assertTrue(utils.is_sorted(list(software_mapping), key=utils.version_key),
                            f"Kubernetes versions for {plugin!r} are not sorted")

            if plugin == 'nginx-ingress-controller':
                self.assertEqual(expected_mapping[plugin]['webhook-version'],
                                 actual_mapping.get('webhook-version'),
                                 f"Webhook version for {plugin!r} and Kubernetes {ver} was not synced")
            if plugin == 'kubernetes-dashboard':
                self.assertEqual(expected_mapping[plugin]['metrics-scraper-version'],
                                 actual_mapping.get('metrics-scraper-version'),
                                 f"Metrics Scraper version for {plugin!r} and Kubernetes {ver} was not synced")
            if plugin == 'local-path-provisioner':
                self.assertEqual(expected_mapping[plugin]['busybox-version'],
                                 actual_mapping.get('busybox-version'),
                                 f"Busybox version for {plugin!r} and Kubernetes {ver} was not synced")

    def _check_added_thirdparties(self, ver: str, from_ver: str):
        for thirdparty in ('kubeadm', 'kubelet', 'kubectl', 'calicoctl', 'crictl'):
            software_mapping = self.compatibility.stored['thirdparties.yaml'][thirdparty]
            actual_mapping = software_mapping.get(ver, {})
            original_mapping = ORIGINAL_COMPATIBILITY_MAPS['thirdparties.yaml'][thirdparty][from_ver]
            expected_sha1 = 'fake-sha1'
            if thirdparty in ('calicoctl', 'crictl'):
                expected_sha1 = original_mapping['sha1']
            self.assertEqual(expected_sha1,
                             actual_mapping.get('sha1'),
                             f"SHA1 for {thirdparty!r} and Kubernetes {ver} was not calculated")
            self.assertTrue(utils.is_sorted(list(software_mapping), key=utils.version_key),
                            f"Kubernetes versions for {thirdparty!r} are not sorted")

            if thirdparty in ('calicoctl', 'crictl'):
                self.assertEqual(original_mapping['version'],
                                 actual_mapping.get('version'),
                                 f"Version for {thirdparty!r} and Kubernetes {ver} was not synced")

    def _check_added_k8s_images(self, ver: str, from_ver: str):
        for k8s_image in ('kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kube-proxy',
                          'pause', 'etcd', 'coredns/coredns'):
            software_mapping = self.compatibility.stored['kubernetes_images.yaml'][k8s_image]
            actual_mapping = software_mapping.get(ver, {})
            self.assertEqual(f"fake-{k8s_image}-version",
                             actual_mapping.get('version'),
                             f"Version for {k8s_image!r} and Kubernetes {ver} was not synced")
            self.assertTrue(utils.is_sorted(list(software_mapping), key=utils.version_key),
                            f"Kubernetes versions for {k8s_image!r} are not sorted")

    def _check_added_packages(self, ver: str, from_ver: str):
        for package in ('docker', 'containerd', 'containerdio'):
            software_mapping = self.compatibility.stored['packages.yaml'][package]
            actual_mapping = software_mapping.get(ver, {})
            original_mapping = ORIGINAL_COMPATIBILITY_MAPS['packages.yaml'][package][from_ver]
            for version_key, expected_version in original_mapping.items():
                self.assertEqual(expected_version,
                                 actual_mapping.get(version_key),
                                 f"{version_key} for {package!r} and Kubernetes {ver} was not synced")
            self.assertTrue(utils.is_sorted(list(software_mapping), key=utils.version_key),
                            f"Kubernetes versions for {package!r} are not sorted")

    def test_compatibility_mapping_remove_version(self):
        k8s_oldest = self.k8s_versions()[0]
        k8s_remove = []
        for k8s_version in self.k8s_versions():
            if utils.minor_version(k8s_version) == utils.minor_version(k8s_oldest):
                k8s_remove.append(k8s_version)
                del self.compatibility_map()[k8s_version]

        self.run_sync()
        for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
            for software_name, mapping in self.compatibility.stored[config_filename].items():
                if software_name in ('haproxy', 'keepalived'):
                    continue

                for k8s_version in k8s_remove:
                    self.assertNotIn(k8s_version, mapping,
                                     f"Kubernetes {k8s_version} was not removed from {config_filename}.")

    def test_compatibility_mapping_update_plugins(self):
        k8s_latest = self.k8s_versions()[-1]
        mapping = self.compatibility_map()[k8s_latest]

        expected_mapping = {}
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            new_version = mapping[plugin]
            while any(new_version == v[plugin] for v in self.compatibility_map().values()):
                new_version = test_utils.increment_version(new_version)

            mapping[plugin] = new_version
            expected_mapping[plugin] = {'version': new_version}
            if plugin == 'nginx-ingress-controller':
                expected_mapping[plugin]['webhook-version'] = 'fake-webhook-version'
            if plugin == 'kubernetes-dashboard':
                expected_mapping[plugin]['metrics-scraper-version'] = 'fake-metrics-scraper-version'
            if plugin == 'local-path-provisioner':
                expected_mapping[plugin]['busybox-version'] = '1.34.1'

        tracker = self.run_sync()
        self._check_added_plugins_by_mapping(k8s_latest, expected_mapping)

        requirements = tracker.get_changed_software_requirements()
        self.assertEqual([k8s_latest], list(requirements), "Unexpected Kubernetes versions were changed")
        expected_software = {'calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'}
        self.assertEqual(expected_software,
                         {name for name, _ in requirements[k8s_latest]},
                         "Unexpected software was changed")

    def test_compatibility_mapping_update_extra_mapping(self):
        k8s_latest = self.k8s_versions()[-1]
        mapping = self.compatibility_map()[k8s_latest]

        expected_versions = {}
        for software in (
                'crictl',
                'webhook', 'metrics-scraper', 'busybox',
                # 'pause',
        ):
            new_version = mapping.get(software, 'v1.2.3')
            while any(new_version == v.get(software) for v in self.compatibility_map().values()):
                new_version = test_utils.increment_version(new_version)

            mapping[software] = new_version
            expected_versions[software] = new_version

        self.run_sync()
        thirdparties_mapping = self.compatibility.stored['thirdparties.yaml']
        self.assertEqual(expected_versions['crictl'],
                         thirdparties_mapping['crictl'][k8s_latest].get('version'),
                         f"'crictl' version for Kubernetes {k8s_latest} was not synced")

        # kubernetes_images_mapping = self.compatibility.stored['kubernetes_images.yaml']
        # self.assertEqual(expected_versions['pause'],
        #                  kubernetes_images_mapping['pause'][k8s_latest].get('version'),
        #                  f"'pause' version for Kubernetes {k8s_latest} was not synced")

        plugin_mapping = self.compatibility.stored['plugins.yaml']
        self.assertEqual(expected_versions['webhook'],
                         plugin_mapping['nginx-ingress-controller'][k8s_latest].get('webhook-version'),
                         f"Webhook version for 'nginx-ingress-controller' and Kubernetes {k8s_latest} was not synced")
        self.assertEqual(expected_versions['metrics-scraper'],
                         plugin_mapping['kubernetes-dashboard'][k8s_latest].get('metrics-scraper-version'),
                         f"Metrics Scraper version for 'kubernetes-dashboard' and Kubernetes {k8s_latest} was not synced")
        self.assertEqual(expected_versions['busybox'],
                         plugin_mapping['local-path-provisioner'][k8s_latest].get('busybox-version'),
                         f"Busybox version for 'local-path-provisioner' and Kubernetes {k8s_latest} was not synced")

    def test_new_unexpected_image(self):
        unexpected_image = 'unexpected/image:1.2.3'
        for test_identity in builtin.MANIFEST_PROCESSOR_PROVIDERS:
            with self.subTest(test_identity.name):
                class FakeManifestResolver(ManifestResolver):
                    def _resolve(self, manifest_identity: Identity, plugin_version: str) -> Manifest:
                        if manifest_identity != test_identity:
                            return FAKE_CACHED_MANIFEST_RESOLVER._resolve(manifest_identity, plugin_version)

                        manifest = FakeManifest(manifest_identity, plugin_version)
                        manifest.images.append(unexpected_image)
                        return manifest

                self.manifest_resolver = FakeManifestResolver()
                with self.assertRaisesRegex(Exception, ERROR_UNEXPECTED_IMAGE.format(
                        image=unexpected_image, manifest=test_identity.name)):
                    self.run_sync()

    def test_images_unexpected_registry(self):
        class FakeManifestResolver(ManifestResolver):
            def __init__(self, replace: bool):
                super().__init__()
                self.replace = replace

            def _resolve(self, manifest_identity: Identity, plugin_version: str) -> Manifest:
                if manifest_identity != Identity('calico'):
                    return FAKE_CACHED_MANIFEST_RESOLVER._resolve(manifest_identity, plugin_version)

                manifest = FakeManifest(manifest_identity, plugin_version)
                if self.replace:
                    for i, image in enumerate(manifest.images):
                        manifest.images[i] = image.replace('docker.io', 'k8s.gcr.io')
                return manifest

        self.manifest_resolver = FakeManifestResolver(False)
        self.run_sync()
        self.manifest_resolver = FakeManifestResolver(True)
        with self.assertRaisesRegex(Exception, ERROR_UNEXPECTED_IMAGE.format(image='.*', manifest="calico")):
            self.run_sync()

    def test_remove_intermediate_version(self):
        k8s_versions = self.k8s_versions()
        if len(k8s_versions) == 1:
            self.skipTest("Cannot remove intermediate Kubernetes version.")

        k8s_intermediate = k8s_versions[1]
        del self.compatibility_map()[k8s_intermediate]

        with self.assertRaisesRegex(Exception, ERROR_PREVIOUS_MINOR.format(
                version=re.escape(k8s_intermediate), previous_versions='.*')):
            self.run_sync()

    def test_mapped_software_not_ascending_order(self):
        if len(self.k8s_versions()) == 1:
            self.skipTest("Cannot check software ascending order for the only Kubernetes version.")

        for software_name in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner',
                              'crictl'):
            with self.subTest(software_name):
                k8s_oldest = self.k8s_versions()[0]
                k8s_latest = self.k8s_versions()[-1]
                self.kubernetes_versions = FakeKubernetesVersions()
                software_latest = self.compatibility_map()[k8s_latest][software_name]
                new_software_version = test_utils.increment_version(software_latest)
                self.compatibility_map()[k8s_oldest][software_name] = new_software_version

                error_msg_pattern = plugins.ERROR_ASCENDING_VERSIONS
                if software_name == 'crictl':
                    error_msg_pattern = thirdparties.ERROR_ASCENDING_VERSIONS

                kwargs = {
                    'thirdparty': re.escape(software_name), 'plugin': re.escape(software_name),
                    'older_version': re.escape(new_software_version), 'older_k8s_version': re.escape(k8s_oldest),
                    'newer_version': '.*', 'newer_k8s_version': '.*',
                }
                with self.assertRaisesRegex(Exception, error_msg_pattern.format(**kwargs)):
                    self.run_sync()

    def test_plugins_suspicious_aba_extra_images(self):
        if len(self.k8s_versions()) < 3:
            self.skipTest("Cannot check suspicions A -> B -> A versions of extra images,")

        plugin_images = {
            'nginx-ingress-controller': 'webhook',
            'kubernetes-dashboard': 'metrics-scraper',
            'local-path-provisioner': 'busybox'
        }
        for plugin, extra_image in plugin_images.items():
            with self.subTest(plugin):
                self.kubernetes_versions = FakeKubernetesVersions()
                self.compatibility_map()[self.k8s_versions()[0]][extra_image] = 'A'
                self.compatibility_map()[self.k8s_versions()[1]][extra_image] = 'B'
                self.compatibility_map()[self.k8s_versions()[-1]][extra_image] = 'A'

                kwargs = {
                    'image': re.escape(extra_image), 'plugin': re.escape(plugin),
                    'version_A': 'A', 'version_B': '.*',
                    'older_k8s_version': re.escape(self.k8s_versions()[0]),
                    'newer_k8s_version': re.escape(self.k8s_versions()[-1]),
                    'k8s_version': '.*',
                }
                with self.assertRaisesRegex(Exception, ERROR_SUSPICIOUS_ABA_VERSIONS.format(**kwargs)):
                    self.run_sync()

    def test_manifests_enrichment_add_new_version(self):
        k8s_latest = self.k8s_versions()[-1]
        new_version = test_utils.increment_version(k8s_latest)
        self.compatibility_map()[new_version] = deepcopy(self.compatibility_map()[k8s_latest])

        self.manifests_enrichment = ManifestsEnrichment()

        with self._mock_globals_load_compatibility_map(), self._mock_globals_load_kubernetes_versions(), \
                self._mock_manifest_processor_enrich() as enrich_called:
            self.run_sync()
            for manifest_identity in builtin.MANIFEST_PROCESSOR_PROVIDERS:
                plugin = manifest_identity.plugin_name
                expected_versions = [ORIGINAL_COMPATIBILITY_MAPS['plugins.yaml'][plugin][k8s_latest]['version']]
                self.assertEqual(expected_versions,
                                 enrich_called.get(manifest_identity),
                                 f"Enrichment of {manifest_identity.name!r} was not called with versions {expected_versions}")

    def test_manifests_enrichment_update_plugin_versions(self):
        plugin = None
        plugin_versions = set()
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            plugin_versions = set(v[plugin] for v in self.compatibility_map().values())
            if len(plugin_versions) > 1:
                break
        else:
            self.skipTest('All plugins have the only version. '
                          'It is not possible to vary the version and run the enrichment.')

        k8s_oldest = self.k8s_versions()[0]
        plugin_oldest = self.compatibility_map()[k8s_oldest][plugin]
        plugin_versions = sorted(plugin_versions, key=utils.version_key)
        plugin_versions.remove(plugin_oldest)
        new_plugin_version = list(plugin_versions)[0]

        k8s_update = []
        for k8s_version in self.k8s_versions():
            if self.compatibility_map()[k8s_version][plugin] == plugin_oldest:
                k8s_update.append(k8s_version)
                self.compatibility_map()[k8s_version][plugin] = new_plugin_version

        self.manifests_enrichment = ManifestsEnrichment()

        with self._mock_globals_load_compatibility_map(), self._mock_globals_load_kubernetes_versions(), \
                self._mock_manifest_processor_enrich() as enrich_called:
            self.run_sync()
            plugin_identities = plugins.get_manifest_identities(plugin)
            self.assertTrue(len(plugin_identities) >= 1,
                            f"No manifests are detected for {plugin} plugin")
            self.assertEqual(set(plugin_identities), set(enrich_called.keys()),
                             "Enrichment is called for unexpected manifests")
            for plugin_identity in plugin_identities:
                self.assertEqual({new_plugin_version},
                                 set(enrich_called[plugin_identity]),
                                 f"Enrichment of {plugin_identity.name!r} was not called with version {new_plugin_version}")

    def test_upgrade_config_update_software(self):
        k8s_update = []
        if len(self.k8s_versions()) > 1:
            k8s_update.append(self.k8s_versions()[-2])
        k8s_update.append(self.k8s_versions()[-1])
        k8s_update.sort(key=utils.version_key)

        for software in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner',
                         'crictl'):
            if software == 'crictl':
                self.upgrade_config.config['thirdparties'][software] = []
            else:
                self.upgrade_config.config['plugins'][software] = []

            for k8s_version in k8s_update:
                mapping = self.compatibility_map()[k8s_version]
                new_version = mapping[software]
                while any(new_version == v[software] for v in self.compatibility_map().values()):
                    new_version = test_utils.increment_version(new_version)
                mapping[software] = new_version

        self.run_sync()

        for software in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner',
                         'crictl'):
            if software == 'crictl':
                list_for_upgrade = self.upgrade_config.config['thirdparties'][software]
            else:
                list_for_upgrade = self.upgrade_config.config['plugins'][software]

            self.assertEqual(k8s_update, list_for_upgrade,
                             f"Some kubernetes versions for {software!r} were not scheduled for upgrade.")

    def test_upgrade_config_update_plugin_extra_images(self):
        k8s_latest = self.k8s_versions()[-1]

        mapping = self.compatibility_map()[k8s_latest]
        for image_name in ('webhook', 'metrics-scraper', 'busybox'):
            new_version = mapping.get(image_name, 'v1.2.3')
            while any(new_version == v.get(image_name) for v in self.compatibility_map().values()):
                new_version = test_utils.increment_version(new_version)
            mapping[image_name] = new_version

        for plugin_name in self.upgrade_config.config['plugins']:
            self.upgrade_config.config['plugins'][plugin_name] = []

        self.run_sync()

        for plugin_name in ('nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            list_for_upgrade = self.upgrade_config.config['plugins'][plugin_name]
            self.assertEqual([k8s_latest], list_for_upgrade,
                             f"Some kubernetes versions for {plugin_name!r} were not scheduled for upgrade.")

        self.assertEqual([], self.upgrade_config.config['plugins']['calico'],
                         f"Unexpected upgrade of 'calico'")

    @contextmanager
    def _mock_manifest_processor_enrich(self) -> ContextManager[Dict[Identity, List[str]]]:
        processor_enrich_orig = Processor.enrich
        enrich_called = {}

        def processor_enrich_mocked(processor: Processor):
            enrich_called.setdefault(processor.manifest_identity, []).append(processor.get_version())
            return processor_enrich_orig(processor)

        with mock.patch.object(Processor, processor_enrich_orig.__name__, new=processor_enrich_mocked):
            yield enrich_called

    @contextmanager
    def _mock_globals_load_kubernetes_versions(self):
        backup = deepcopy(static.KUBERNETES_VERSIONS)
        def load_kubernetes_versions_mocked() -> dict:
            return self._convert_ruamel_pyyaml(self.kubernetes_versions.stored)

        try:
            with mock.patch.object(static, static.load_kubernetes_versions.__name__,
                                   side_effect=load_kubernetes_versions_mocked):
                yield
        finally:
            static.KUBERNETES_VERSIONS = backup

    @contextmanager
    def _mock_globals_load_compatibility_map(self):
        def load_compatibility_map_mocked(filename: str) -> dict:
            return self._convert_ruamel_pyyaml(self.compatibility.stored[filename])

        with test_utils.backup_globals(), \
                mock.patch.object(static, static.load_compatibility_map.__name__,
                                  side_effect=load_compatibility_map_mocked):
            yield

    def _convert_ruamel_pyyaml(self, source: CommentedMap) -> dict:
        stream = io.StringIO()
        utils.yaml_structure_preserver().dump(source, stream)
        return yaml.safe_load(io.StringIO(stream.getvalue()))

    def run_sync(self) -> SummaryTracker:
        return FakeSynchronization(
            self.compatibility,
            self.kubernetes_versions,
            self.manifest_resolver,
            self.manifests_enrichment,
            self.upgrade_config,
        ).run()

    def compatibility_map(self) -> dict:
        return self.kubernetes_versions.kubernetes_versions['compatibility_map']

    def k8s_versions(self) -> List[str]:
        return sorted(self.compatibility_map(), key=utils.version_key)


if __name__ == '__main__':
    unittest.main()
