import os
import tarfile
import tempfile
from typing import List, Tuple, Dict

from kubemarine import demo
from kubemarine.core import static, utils, log
from kubemarine.plugins import builtin
from kubemarine.plugins.manifest import Manifest, get_default_manifest_path
from . import CompatibilityMap
from ..shell import curl, info, run, TEMP_FILE, SYNC_CACHE
from ..tracker import ChangesTracker


PLUGINS = ['calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner']


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


def download_manifest_if_necessary(plugin_name: str, plugin_version: str, force: bool) -> str:
    manifest_path = get_default_manifest_path(plugin_name, plugin_version)
    if not os.path.exists(manifest_path) or force:
        manifest_local_path = resolve_local_path(plugin_name, plugin_version)
        print(f"Copying {os.path.basename(manifest_local_path)} to {manifest_path}")
        with utils.open_external(manifest_local_path, 'r') as source, \
                utils.open_internal(manifest_path, 'w') as target:
            target.write(source.read())

        run(['git', 'add', manifest_path])

    return manifest_path


def resolve_plugin_manifests(kubernetes_versions: dict, plugins: List[str], k8s_versions: List[str],
                             refresh_manifests=False) -> Dict[Tuple[str, str], Manifest]:
    plugin_manifests = {}
    for plugin_name in plugins:
        for k8s_version in k8s_versions:
            plugin_version = kubernetes_versions[k8s_version][plugin_name]
            plugin_identity = (plugin_name, plugin_version)
            if plugin_identity in plugin_manifests:
                continue

            manifest_path = download_manifest_if_necessary(plugin_name, plugin_version, force=refresh_manifests)
            with utils.open_internal(manifest_path, 'r') as stream:
                plugin_manifests[plugin_identity] = Manifest(stream)

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
        raise Exception(f"Image {image!r} of 'calico' is not expected")

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
            raise Exception(f"Image {image!r} of 'nginx-ingress-controller' is not expected")

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
            raise Exception(f"Image {image!r} of 'kubernetes-dashboard' is not expected")

    return extra_images


def local_path_provisioner_extract_images(images: List[str], plugin_version: str) -> Dict[str, str]:
    expected_images = ['rancher/local-path-provisioner']
    expected_images = [f"{image}:{plugin_version}" for image in expected_images]
    for image in images:
        if image in expected_images:
            continue
        raise Exception(f"Image {image!r} of 'local-path-provisioner' is not expected")

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


def sync(tracker: ChangesTracker, kubernetes_versions: dict,
         refresh_manifests=False):
    """
    Download and save plugin manifests if necessary, and actualize compatibility_map of all plugins.
    # TODO if plugin versions are changed, it is necessary to write patch that will reinstall corresponding plugins.
    """
    k8s_versions = list(kubernetes_versions)
    plugin_manifests = resolve_plugin_manifests(kubernetes_versions, PLUGINS, k8s_versions, refresh_manifests)

    compatibility_map = CompatibilityMap(tracker, "plugins.yaml", PLUGINS)
    for plugin_name in PLUGINS:
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

    compatibility_map.flush()


def try_manifest_enrichment(k8s_version: str, plugin_name: str):
    # Generate fake cluster and run plugin manifest enrichment on it
    info(f"Trying default enrichment of {plugin_name!r} manifest for Kubernetes {k8s_version}")

    inventory = demo.generate_inventory(**demo.ALLINONE)

    inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version
    # TODO in future we should enable suitable admission implementation by default
    if utils.minor_version_key(k8s_version) >= (1, 25):
        inventory.setdefault('rbac', {})['admission'] = 'pss'

    context = demo.create_silent_context([
        '--log', 'stdout;level=error;colorize=false;correct_newlines=true;format=%(levelname)s %(message)s'
    ])
    cluster = demo.new_cluster(inventory, context=context)

    class ConsoleLogger(log.VerboseLogger):
        def verbose(self, msg: str, *args, **kwargs):
            print(msg)

    processor = builtin.get_manifest_processor(ConsoleLogger(), cluster.inventory, plugin_name)
    processor.enrich()
