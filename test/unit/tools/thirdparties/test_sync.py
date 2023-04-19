import io
import unittest
from contextlib import contextmanager
from copy import deepcopy
from typing import List, Dict, ContextManager
from unittest import mock

import yaml

from kubemarine.core import utils, static
from kubemarine.plugins.manifest import Manifest, Processor
from scripts.thirdparties.src.software.plugins import (
    ManifestResolver, ERROR_UNEXPECTED_IMAGE, ManifestsEnrichment
)
from scripts.thirdparties.src.tracker import ChangesTracker
from test.unit.tools.thirdparties.stub import (
    FakeSynchronization, FakeInternalCompatibility, FakeKubernetesVersions,
    FAKE_CACHED_MANIFEST_RESOLVER, FakeManifest, NoneManifestsEnrichment
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

    def test_clean_run_changes_nothing(self):
        self.run_sync()
        for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
            self.assertTrue(ORIGINAL_COMPATIBILITY_MAPS[config_filename] == self.compatibility.stored[config_filename],
                            f"{config_filename} was changed without any change in kubernetes_versions.yaml")

    def test_kubernetes_versions_add_minor_version(self):
        k8s_latest = self.k8s_versions()[-1]
        new_version = self.increment_version(k8s_latest, minor=True)
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
                new_versions[i] = ver = self.increment_version(ver)

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
        for package in ('docker', 'containerd', 'containerdio', 'podman'):
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
        del self.compatibility_map()[k8s_oldest]

        self.run_sync()
        for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
            for software_name, mapping in self.compatibility.stored[config_filename].items():
                if software_name in ('haproxy', 'keepalived'):
                    continue

                self.assertNotIn(k8s_oldest, mapping,
                                 f"Kubernetes {k8s_oldest} was not removed from {config_filename}.")

    def test_compatibility_mapping_update_plugins(self):
        k8s_latest = self.k8s_versions()[-1]
        mapping = self.compatibility_map()[k8s_latest]

        expected_mapping = {}
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            new_version = mapping[plugin]
            while any(new_version == v[plugin] for v in self.compatibility_map().values()):
                new_version = self.increment_version(new_version)

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
        for software in ('crictl', 'pause', 'webhook', 'metrics-scraper', 'busybox'):
            new_version = mapping.get(software, '1.2.3')
            while any(new_version == v.get(software) for v in self.compatibility_map().values()):
                new_version = self.increment_version(new_version)

            mapping[software] = new_version
            expected_versions[software] = new_version

        self.run_sync()
        thirdparties_mapping = self.compatibility.stored['thirdparties.yaml']
        self.assertEqual(expected_versions['crictl'],
                         thirdparties_mapping['crictl'][k8s_latest].get('version'),
                         f"'crictl' version for Kubernetes {k8s_latest} was not synced")

        kubernetes_images_mapping = self.compatibility.stored['kubernetes_images.yaml']
        self.assertEqual(expected_versions['pause'],
                         kubernetes_images_mapping['pause'][k8s_latest].get('version'),
                         f"'pause' version for Kubernetes {k8s_latest} was not synced")

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
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            with self.subTest(plugin):
                class FakeManifestResolver(ManifestResolver):
                    def resolve(self, plugin_name: str, plugin_version: str) -> Manifest:
                        if plugin_name != plugin:
                            return FAKE_CACHED_MANIFEST_RESOLVER.resolve(plugin_name, plugin_version)

                        manifest = FakeManifest(plugin_name, plugin_version)
                        manifest.images.append(unexpected_image)
                        return manifest

                self.manifest_resolver = FakeManifestResolver()
                with self.assertRaisesRegex(Exception, ERROR_UNEXPECTED_IMAGE.format(image=unexpected_image, plugin=plugin)):
                    self.run_sync()

    def test_images_unexpected_registry(self):
        class FakeManifestResolver(ManifestResolver):
            def __init__(self, replace: bool):
                super().__init__()
                self.replace = replace

            def resolve(self, plugin_name: str, plugin_version: str) -> Manifest:
                if plugin_name != 'calico':
                    return FAKE_CACHED_MANIFEST_RESOLVER.resolve(plugin_name, plugin_version)

                manifest = FakeManifest(plugin_name, plugin_version)
                if self.replace:
                    for i, image in enumerate(manifest.images):
                        manifest.images[i] = image.replace('docker.io', 'k8s.gcr.io')
                return manifest

        self.manifest_resolver = FakeManifestResolver(False)
        self.run_sync()
        self.manifest_resolver = FakeManifestResolver(True)
        with self.assertRaisesRegex(Exception, ERROR_UNEXPECTED_IMAGE.format(image='.*', plugin='calico')):
            self.run_sync()

    def test_manifests_enrichment_add_new_version(self):
        k8s_latest = self.k8s_versions()[-1]
        new_version = self.increment_version(k8s_latest)
        self.compatibility_map()[new_version] = deepcopy(self.compatibility_map()[k8s_latest])

        self.manifests_enrichment = ManifestsEnrichment()

        with self._mock_globals_reload_compatibility_map(), \
                self._mock_manifest_processor_enrich() as enrich_called:
            self.run_sync()
            for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
                expected_versions = [ORIGINAL_COMPATIBILITY_MAPS['plugins.yaml'][plugin][k8s_latest]['version']]
                self.assertEqual(expected_versions,
                                 enrich_called.get(plugin),
                                 f"Enrichment of {plugin!r} was not called with versions {expected_versions}")

    def test_manifests_enrichment_update_plugin_versions(self):
        plugin = None
        plugin_versions = []
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            plugin_versions = set(v[plugin] for v in self.compatibility_map().values())
            if len(plugin_versions) > 1:
                break
        else:
            self.skipTest('All plugins have the only version. '
                          'It is not possible to vary the version and run the enrichment.')

        k8s_latest = self.k8s_versions()[-1]
        plugin_version = self.compatibility_map()[k8s_latest][plugin]
        plugin_versions.remove(plugin_version)
        new_plugin_version = list(plugin_versions)[0]
        self.compatibility_map()[k8s_latest][plugin] = new_plugin_version

        self.manifests_enrichment = ManifestsEnrichment()

        with self._mock_globals_reload_compatibility_map(), \
                self._mock_manifest_processor_enrich() as enrich_called:
            self.run_sync()
            self.assertEqual([plugin], list(enrich_called.keys()),
                             "Enrichment is called for unexpected plugins")
            self.assertEqual([new_plugin_version],
                             enrich_called[plugin],
                             f"Enrichment of {plugin!r} was not called with version {new_plugin_version}")

    @contextmanager
    def _mock_manifest_processor_enrich(self) -> ContextManager[Dict[str, List[str]]]:
        processor_enrich_orig = Processor.enrich
        enrich_called = {}

        def processor_enrich_mocked(processor: Processor):
            enrich_called.setdefault(processor.plugin_name, []).append(processor.get_version())
            return processor_enrich_orig(processor)

        with mock.patch.object(Processor, processor_enrich_orig.__name__, new=processor_enrich_mocked):
            yield enrich_called

    @contextmanager
    def _mock_globals_reload_compatibility_map(self):
        backup = deepcopy(static.GLOBALS)
        def load_compatibility_map_mocked(filename: str) -> dict:
            stream = io.StringIO()
            utils.yaml_structure_preserver().dump(self.compatibility.stored[filename], stream)
            return yaml.safe_load(io.StringIO(stream.getvalue()))

        try:
            with mock.patch.object(static, static.load_compatibility_map.__name__,
                                   side_effect=load_compatibility_map_mocked):
                yield
        finally:
            static.GLOBALS = backup

    def run_sync(self) -> ChangesTracker:
        return FakeSynchronization(
            self.compatibility,
            self.kubernetes_versions,
            self.manifest_resolver,
            self.manifests_enrichment
        ).run()

    def compatibility_map(self) -> dict:
        return self.kubernetes_versions.kubernetes_versions['compatibility_map']

    def k8s_versions(self) -> List[str]:
        return list(sorted(self.compatibility_map(), key=utils.version_key))

    def increment_version(self, version: str, minor=False):
        new_version = list(utils.version_key(version))
        if minor:
            new_version[1] += 1
        else:
            new_version[2] += 1
        return f"v{'.'.join(map(str, new_version))}"
