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
from typing import List, Tuple, Dict

from kubemarine import demo
from kubemarine.core import static, utils, log
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Manifest, get_default_manifest_path
from . import SoftwareType, InternalCompatibility
from ..shell import curl, info, run, TEMP_FILE, SYNC_CACHE
from ..tracker import ChangesTracker


ERROR_UNEXPECTED_IMAGE = "Image '{image}' of '{plugin}' is not expected"


class ManifestResolver:
    def __init__(self, refresh=False):
        self.refresh = refresh

    def resolve(self, plugin_name: str, plugin_version: str) -> Manifest:
        manifest_path = get_default_manifest_path(plugin_name, plugin_version)
        if not os.path.exists(manifest_path) or self.refresh:
            manifest_local_path = resolve_local_path(plugin_name, plugin_version)
            print(f"Copying {os.path.basename(manifest_local_path)} to {manifest_path}")
            with utils.open_external(manifest_local_path, 'r') as source, \
                    utils.open_internal(manifest_path, 'w') as target:
                target.write(source.read())

            run(['git', 'add', manifest_path])

        with utils.open_internal(manifest_path, 'r') as stream:
            return Manifest(stream)


class ManifestsEnrichment:
    def run(self, tracker: ChangesTracker):
        for k8s_version in tracker.all_k8s_versions:
            for plugin_name in list(static.GLOBALS['plugins']):
                if tracker.is_software_changed(k8s_version, plugin_name):
                    try_manifest_enrichment(k8s_version, plugin_name)


class Plugins(SoftwareType):
    def __init__(self, compatibility: InternalCompatibility, manifest_resolver: ManifestResolver):
        super().__init__(compatibility)
        self.manifest_resolver = manifest_resolver

    def sync(self, tracker: ChangesTracker):
        """
        Download and save plugin manifests if necessary, and actualize compatibility_map of all plugins.
        # TODO if plugin versions are changed, it is necessary to write patch that will reinstall corresponding plugins.
        """
        kubernetes_versions = tracker.kubernetes_versions
        k8s_versions = tracker.all_k8s_versions
        plugins = list(static.GLOBALS['plugins'])
        plugin_manifests = resolve_plugin_manifests(self.manifest_resolver, kubernetes_versions)

        compatibility_map = self.compatibility.load(tracker, "plugins.yaml", plugins)
        for plugin_name in plugins:
            compatibility_map.prepare_software_mapping(plugin_name, k8s_versions)

            for k8s_version in k8s_versions:
                k8s_settings = kubernetes_versions[k8s_version]
                plugin_version = k8s_settings[plugin_name]
                plugin_identity = (plugin_name, plugin_version)
                manifest = plugin_manifests[plugin_identity]

                new_settings = {
                    'version': plugin_version
                }
                extra_images = get_extra_images(manifest, plugin_name, plugin_version)
                for image_name, image_version in extra_images.items():
                    if image_name in k8s_settings:
                        image_version = k8s_settings[image_name]

                    new_settings[f"{image_name}-version"] = image_version

                compatibility_map.reset_software_settings(plugin_name, k8s_version, new_settings)

        self.compatibility.store(compatibility_map)


def resolve_local_path(plugin_name: str, plugin_version: str) -> str:
    filename = f"{plugin_name}-{plugin_version}"
    target_file = os.path.join(SYNC_CACHE, filename)
    if os.path.exists(target_file):
        return target_file

    source_settings = static.GLOBALS['plugins'][plugin_name]['source']
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

    print(f"Downloading manifest for plugin {plugin_name!r} of version {plugin_version} from {url}")
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


def resolve_plugin_manifests(manifest_resolver: ManifestResolver, kubernetes_versions: dict) \
        -> Dict[Tuple[str, str], Manifest]:
    plugin_manifests = {}
    for plugin_name in static.GLOBALS['plugins']:
        for k8s_version in kubernetes_versions:
            plugin_version = kubernetes_versions[k8s_version][plugin_name]
            plugin_identity = (plugin_name, plugin_version)
            if plugin_identity in plugin_manifests:
                continue

            plugin_manifests[plugin_identity] = manifest_resolver.resolve(plugin_name, plugin_version)

    return plugin_manifests


def calico_extract_images(images: List[str], plugin_version: str) -> Dict[str, str]:
    expected_images = [
        'calico/pod2daemon-flexvol',
        'calico/typha', 'calico/cni', 'calico/node', 'calico/kube-controllers',
    ]
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, plugin='calico'))

    return {}


def nginx_ingress_extract_images(images: List[str], plugin_version: str) -> Dict[str, str]:
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
            raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, plugin='nginx-ingress-controller'))

    return extra_images


def dashboard_extract_images(images: List[str], plugin_version: str) -> Dict[str, str]:
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
            raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, plugin='kubernetes-dashboard'))

    return extra_images


def local_path_provisioner_extract_images(images: List[str], plugin_version: str) -> Dict[str, str]:
    expected_images = ['rancher/local-path-provisioner']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(ERROR_UNEXPECTED_IMAGE.format(image=image, plugin='local-path-provisioner'))

    return {'busybox': '1.34.1'}


def get_extra_images(manifest: Manifest, plugin_name: str, plugin_version: str) -> Dict[str, str]:
    images = []
    for image in manifest.get_all_container_images():
        image = image.split('@sha256:')[0]
        image = image.replace('docker.io/', '')
        # Currently only 'nginx-ingress-controller' contains images from GCR registry.
        # If some new image in this registry appear, we should emphasize this explicitly,
        # adopt the synchronization tool, and installation.registry of the plugin in defaults.yaml
        if plugin_name == 'nginx-ingress-controller':
            image = image.replace('k8s.gcr.io/', '')
            image = image.replace('registry.k8s.io/', '')

        images.append(image)

    # We should verify that all images are expected.
    # If some new image in the plugin appear, we should emphasize this explicitly,
    # as any new image will require to change defaults.yaml and the enrichment process.
    if plugin_name == 'calico':
        return calico_extract_images(images, plugin_version)
    elif plugin_name == 'nginx-ingress-controller':
        return nginx_ingress_extract_images(images, plugin_version)
    elif plugin_name == 'kubernetes-dashboard':
        return dashboard_extract_images(images, plugin_version)
    elif plugin_name == 'local-path-provisioner':
        return local_path_provisioner_extract_images(images, plugin_version)
    else:
        raise Exception(f"Unsupported plugin {plugin_name!r}")


def try_manifest_enrichment(k8s_version: str, plugin_name: str):
    # Generate fake cluster and run plugin manifest enrichment on it
    info(f"Trying default enrichment of {plugin_name!r} manifest for Kubernetes {k8s_version}")

    inventory = demo.generate_inventory(**demo.ALLINONE)
    inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version

    context = demo.create_silent_context([
        '--log', 'stdout;level=error;colorize=false;correct_newlines=true;format=%(levelname)s %(message)s'
    ])
    cluster = demo.new_cluster(inventory, context=context)

    class ConsoleLogger(log.VerboseLogger):
        def verbose(self, msg: str, *args, **kwargs):
            print(msg)

    processor = builtin.get_manifest_processor(ConsoleLogger(), cluster.inventory, plugin_name)
    processor.enrich()
