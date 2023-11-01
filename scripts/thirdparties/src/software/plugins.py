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

import os
import tarfile
import tempfile
from typing import List, Tuple, Dict, Any

from kubemarine import demo
from kubemarine.core import static, utils, log
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Manifest, get_default_manifest_path, Identity
from . import SoftwareType, InternalCompatibility, CompatibilityMap, UpgradeSoftware, UpgradeConfig
from ..shell import curl, info, run, TEMP_FILE, SYNC_CACHE
from ..tracker import SummaryTracker, ComposedTracker

ERROR_UNEXPECTED_IMAGE = "Image '{image}' for manifest '{manifest}' is not expected"
ERROR_ASCENDING_VERSIONS = \
    "Plugins should have non-decreasing versions. " \
    "Plugin '{plugin}' has version {older_version} for Kubernetes {older_k8s_version}, " \
    "and has lower version {newer_version} for newer Kubernetes {newer_k8s_version}."
ERROR_SUSPICIOUS_ABA_VERSIONS = \
    "Detected suspicious versions of extra plugin images. " \
    "Image '{image}' for plugin '{plugin}' has version {version_A} for Kubernetes {older_k8s_version}, " \
    "version {version_B} for Kubernetes {k8s_version}, " \
    "and again version {version_A} for Kubernetes {newer_k8s_version}."


class ManifestResolver:
    def __init__(self, refresh: bool = False):
        self.refresh = refresh

    def resolve(self, plugin_name: str, plugin_version: str) -> List[Manifest]:
        return [self._resolve(manifest_identity, plugin_version)
                for manifest_identity in get_manifest_identities(plugin_name)]

    def _resolve(self, manifest_identity: Identity, plugin_version: str) -> Manifest:
        manifest_path = get_default_manifest_path(manifest_identity, plugin_version)
        if not os.path.exists(manifest_path) or self.refresh:
            manifest_local_path = resolve_local_path(manifest_identity, plugin_version)
            print(f"Copying {os.path.basename(manifest_local_path)} to {manifest_path}")
            with utils.open_external(manifest_local_path, 'r') as source, \
                    utils.open_internal(manifest_path, 'w') as target:
                target.write(source.read())

            run(['git', 'add', manifest_path])

        with utils.open_internal(manifest_path, 'r') as stream:
            return Manifest(manifest_identity, stream)


class ManifestsEnrichment:
    def run(self, tracker: SummaryTracker) -> None:
        for k8s_version in tracker.all_k8s_versions:
            for plugin_name in list(static.GLOBALS['plugins']):
                if not tracker.is_software_changed(k8s_version, plugin_name):
                    continue

                for manifest_identity in get_manifest_identities(plugin_name):
                    try_manifest_enrichment(k8s_version, manifest_identity)


class Plugins(SoftwareType):
    def __init__(self, compatibility: InternalCompatibility, upgrade_config: UpgradeConfig,
                 manifest_resolver: ManifestResolver):
        super().__init__(compatibility, upgrade_config)
        self.manifest_resolver = manifest_resolver

    @property
    def name(self) -> str:
        return 'plugins'

    def sync(self, summary_tracker: SummaryTracker) -> CompatibilityMap:
        """
        Download and save plugin manifests if necessary, and actualize compatibility_map of all plugins.
        """
        kubernetes_versions = summary_tracker.kubernetes_versions
        k8s_versions = summary_tracker.all_k8s_versions
        plugins = list(static.GLOBALS['plugins'])
        plugin_manifests = resolve_plugin_manifests(self.manifest_resolver, kubernetes_versions)

        upgrade_software = UpgradeSoftware(self.upgrade_config, self.name, plugins)
        upgrade_software.prepare(summary_tracker)

        tracker = ComposedTracker(summary_tracker, upgrade_software)
        compatibility_map = self.compatibility.load(tracker, "plugins.yaml")
        compatibility_map.prepare(summary_tracker, plugins)

        for plugin_name in plugins:
            validate_plugin_versions(kubernetes_versions, plugin_name)
            compatibility_map.prepare_software_mapping(plugin_name, k8s_versions)

            for k8s_version in k8s_versions:
                k8s_settings = kubernetes_versions[k8s_version]
                plugin_version = k8s_settings[plugin_name]
                plugin_identity = (plugin_name, plugin_version)
                manifests = plugin_manifests[plugin_identity]

                new_settings = {
                    'version': plugin_version
                }
                extra_images = get_extra_images(manifests, plugin_version)
                for image_name, image_version in extra_images.items():
                    if image_name in k8s_settings:
                        image_version = k8s_settings[image_name]

                    new_settings[f"{image_name}-version"] = image_version

                compatibility_map.reset_software_settings(plugin_name, k8s_version, new_settings)

            validate_compatibility_map(compatibility_map, plugin_name)

        return compatibility_map


def validate_plugin_versions(kubernetes_versions: Dict[str, Dict[str, str]], plugin_name: str) -> None:
    key = utils.version_key
    k8s_versions = sorted(kubernetes_versions.keys(), key=key)

    for i, older_k8s_version in enumerate(k8s_versions):
        for j in range(i + 1, len(k8s_versions)):
            newer_k8s_version = k8s_versions[j]
            older_version = kubernetes_versions[older_k8s_version][plugin_name]
            newer_version = kubernetes_versions[newer_k8s_version][plugin_name]
            if key(newer_version) < key(older_version):
                raise Exception(ERROR_ASCENDING_VERSIONS.format(
                    plugin=plugin_name,
                    older_k8s_version=older_k8s_version, newer_k8s_version=newer_k8s_version,
                    older_version=older_version, newer_version=newer_version
                ))


def validate_compatibility_map(compatibility_map: CompatibilityMap, plugin_name: str) -> None:
    plugin_mapping: dict = compatibility_map.compatibility_map[plugin_name]
    k8s_versions = list(plugin_mapping)

    extra_images = []
    if plugin_name == 'nginx-ingress-controller':
        extra_images.append('webhook')
    elif plugin_name == 'kubernetes-dashboard':
        extra_images.append('metrics-scraper')
    elif plugin_name == 'local-path-provisioner':
        extra_images.append('busybox')

    for extra_image in extra_images:
        version_key = f"{extra_image}-version"
        for i, newer_k8s_version in enumerate(k8s_versions):
            for j in range(i - 1):
                k8s_version = k8s_versions[i - 1]
                older_k8s_version = k8s_versions[j]
                version_A = plugin_mapping[older_k8s_version][version_key]
                version_B = plugin_mapping[k8s_version][version_key]
                version_A1 = plugin_mapping[newer_k8s_version][version_key]
                if version_A == version_A1 and version_A != version_B:
                    raise Exception(ERROR_SUSPICIOUS_ABA_VERSIONS.format(
                        image=extra_image, plugin=plugin_name,
                        older_k8s_version=older_k8s_version, k8s_version=k8s_version, newer_k8s_version=newer_k8s_version,
                        version_A=version_A, version_B=version_B
                    ))


def get_manifest_identities(plugin_name: str) -> List[Identity]:
    return [Identity(plugin_name, manifest_settings.get('id'))
            for manifest_settings in static.GLOBALS['plugins'][plugin_name]['manifests']]


def resolve_local_path(manifest_identity: Identity, plugin_version: str) -> str:
    plugin_name = manifest_identity.plugin_name
    filename = f"{manifest_identity.name}-{plugin_version}"
    target_file = os.path.join(SYNC_CACHE, filename)
    if os.path.exists(target_file):
        return target_file

    source_settings = next(manifest_settings['source']
                           for manifest_settings in static.GLOBALS['plugins'][plugin_name]['manifests']
                           if manifest_identity.manifest_id == manifest_settings.get('id'))
    minor_version = utils.minor_version(plugin_version)
    if plugin_version in source_settings:
        source = source_settings[plugin_version]
    elif minor_version in source_settings:
        source = source_settings[minor_version]
    else:
        source = source_settings['default']

    url = source
    if isinstance(source, dict):
        url = source['url']
    url = url.format(version=plugin_version)

    print(f"Downloading {manifest_identity.repr_id()} for plugin {plugin_name!r} of version {plugin_version} from {url}")
    curl(url, TEMP_FILE)
    if isinstance(source, dict) and 'extract' in source:
        extract_path = source['extract'].format(version=plugin_version)
        with tempfile.TemporaryDirectory() as tmpdir:
            print(f"Extracting {extract_path}")
            with tarfile.open(TEMP_FILE, 'r:gz') as t:
                t.extract(extract_path, tmpdir)

            os.replace(os.path.join(tmpdir, extract_path), TEMP_FILE)

    os.rename(TEMP_FILE, target_file)

    return target_file


def resolve_plugin_manifests(manifest_resolver: ManifestResolver, kubernetes_versions: Dict[str, Dict[str, str]]) \
        -> Dict[Tuple[str, str], List[Manifest]]:
    plugin_manifests = {}
    for plugin_name in static.GLOBALS['plugins']:
        for k8s_version in kubernetes_versions:
            plugin_version = kubernetes_versions[k8s_version][plugin_name]
            plugin_identity = (plugin_name, plugin_version)
            if plugin_identity in plugin_manifests:
                continue

            plugin_manifests[plugin_identity] = manifest_resolver.resolve(plugin_name, plugin_version)

    return plugin_manifests


def calico_extract_images(images: List[str], manifest_identity: Identity, plugin_version: str) -> Dict[str, str]:
    expected_images = [
        'calico/typha', 'calico/cni', 'calico/node', 'calico/kube-controllers',
    ]
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, manifest=manifest_identity.name))

    return {}


def calico_apiserver_extract_images(images: List[str], manifest_identity: Identity, plugin_version: str) -> Dict[str, str]:
    expected_images = ['calico/apiserver']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, manifest=manifest_identity.name))

    return {}


def nginx_ingress_extract_images(images: List[str], manifest_identity: Identity, plugin_version: str) -> Dict[str, str]:
    expected_images = ['ingress-nginx/controller']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    extra_images = {}
    for image in images:
        if image in expected_images:
            continue
        image_name, version = image.split(':')
        if image_name == 'ingress-nginx/kube-webhook-certgen':
            extra_images['webhook'] = version
        else:
            raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, manifest=manifest_identity.name))

    return extra_images


def dashboard_extract_images(images: List[str], manifest_identity: Identity, plugin_version: str) -> Dict[str, str]:
    expected_images = ['kubernetesui/dashboard']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    extra_images = {}
    for image in images:
        if image in expected_images:
            continue
        image_name, version = image.split(':')
        if image_name == 'kubernetesui/metrics-scraper':
            extra_images['metrics-scraper'] = version
        else:
            raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, manifest=manifest_identity.name))

    return extra_images


def local_path_provisioner_extract_images(images: List[str], manifest_identity: Identity, plugin_version: str) -> Dict[str, str]:
    expected_images = ['rancher/local-path-provisioner']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, manifest=manifest_identity.name))

    return {'busybox': '1.34.1'}


def get_extra_images(manifests: List[Manifest], plugin_version: str) -> Dict[str, str]:
    return dict(item for manifest in manifests
                for item in get_extra_manifest_images(manifest, plugin_version).items())


def get_extra_manifest_images(manifest: Manifest, plugin_version: str) -> Dict[str, str]:
    images = []
    for image in manifest.get_all_container_images():
        image = image.split('@sha256:')[0]
        image = image.replace('docker.io/', '')
        # Currently only 'nginx-ingress-controller' contains images from GCR registry.
        # If some new image in this registry appear, we should emphasize this explicitly,
        # adopt the synchronization tool, and installation.registry of the plugin in defaults.yaml
        if manifest.identity == Identity('nginx-ingress-controller'):
            image = image.replace('k8s.gcr.io/', '')
            image = image.replace('registry.k8s.io/', '')

        images.append(image)

    # We should verify that all images are expected.
    # If some new image in the plugin appear, we should emphasize this explicitly,
    # as any new image will require to change defaults.yaml and the enrichment process.
    if manifest.identity == Identity('calico'):
        return calico_extract_images(images, manifest.identity, plugin_version)
    elif manifest.identity == Identity('calico', 'apiserver'):
        return calico_apiserver_extract_images(images, manifest.identity, plugin_version)
    elif manifest.identity == Identity('nginx-ingress-controller'):
        return nginx_ingress_extract_images(images, manifest.identity, plugin_version)
    elif manifest.identity == Identity('kubernetes-dashboard'):
        return dashboard_extract_images(images, manifest.identity, plugin_version)
    elif manifest.identity == Identity('local-path-provisioner'):
        return local_path_provisioner_extract_images(images, manifest.identity, plugin_version)
    else:
        raise Exception(f"Unsupported manifest {manifest.identity.name!r}")


def try_manifest_enrichment(k8s_version: str, manifest_identity: Identity) -> None:
    # Generate fake cluster and run plugin manifest enrichment on it
    info(f"Trying default enrichment of {manifest_identity.name!r} manifest for Kubernetes {k8s_version}")

    inventory = demo.generate_inventory(**demo.ALLINONE)
    inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version

    context = demo.create_silent_context([
        '--log', 'stdout;level=error;colorize=false;correct_newlines=true;format=%(levelname)s %(message)s'
    ])
    cluster = demo.new_cluster(inventory, context=context)

    class ConsoleLogger(log.VerboseLogger):
        def verbose(self, msg: object, *args: object, **kwargs: Any) -> None:
            print(msg)

    processor = builtin._get_manifest_processor(ConsoleLogger(), cluster.inventory, manifest_identity)
    processor.enrich()
