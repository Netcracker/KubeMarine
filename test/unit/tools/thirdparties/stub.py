import io
import os
from copy import deepcopy
from typing import List, Dict, Tuple, Optional

import yaml
from ruamel.yaml import CommentedMap

from kubemarine.core import static, utils
from kubemarine.plugins.manifest import Manifest, get_default_manifest_path
from scripts.thirdparties.src.compatibility import KubernetesVersions
from scripts.thirdparties.src.run import Synchronization
from scripts.thirdparties.src.software import InternalCompatibility, CompatibilityMap
from scripts.thirdparties.src.software.kubernetes_images import KubernetesImagesResolver
from scripts.thirdparties.src.software.plugins import ManifestResolver, ManifestsEnrichment
from scripts.thirdparties.src.software.thirdparties import ThirdpartyResolver
from scripts.thirdparties.src.tracker import ChangesTracker


class FakeInternalCompatibility(InternalCompatibility):
    def __init__(self):
        self.stored = {}

    def store(self, compatibility_map: CompatibilityMap):
        self.stored[compatibility_map.name] = deepcopy(compatibility_map.compatibility_map)


class FakeKubernetesVersions(KubernetesVersions):
    def __init__(self):
        super().__init__()
        self.stored: Optional[dict] = None

    @property
    def kubernetes_versions(self) -> CommentedMap:
        return self._kubernetes_versions

    def store(self) -> None:
        self.stored = deepcopy(self.kubernetes_versions)


class FakeKubernetesImagesResolver(KubernetesImagesResolver):
    with utils.open_internal("resources/configurations/compatibility/internal/kubernetes_images.yaml") as stream:
        kubernetes_images: dict = yaml.safe_load(stream)

    def resolve(self, k8s_version: str) -> List[str]:
        kubernetes_images = FakeKubernetesImagesResolver.kubernetes_images
        if any(k8s_version in mapping for mapping in kubernetes_images.values()):
            return [f"k8s.gcr.io/{name}:{mapping[k8s_version]['version']}"
                    for name, mapping in kubernetes_images.items()
                    if k8s_version in mapping]
        else:
            return [f"k8s.gcr.io/{name}:fake-{name}-version"
                    for name in ['kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'kube-proxy',
                                 'pause', 'etcd', 'coredns/coredns']]


class FakeManifest(Manifest):
    def __init__(self, plugin_name: str, plugin_version: str):
        super().__init__(io.StringIO())
        self.images = self._stub_images(plugin_name, plugin_version)

    def get_all_container_images(self) -> List[str]:
        return self.images

    def _stub_images(self, plugin_name: str, plugin_version: str) -> List[str]:
        if plugin_name == 'calico':
            return [
                f'docker.io/calico/node:{plugin_version}',
                f'docker.io/calico/cni:{plugin_version}',
                f'docker.io/calico/kube-controllers:{plugin_version}',
                f'docker.io/calico/typha:{plugin_version}'
            ]
        elif plugin_name == 'nginx-ingress-controller':
            return [
                f'registry.k8s.io/ingress-nginx/controller:{plugin_version}@sha256:123',
                'registry.k8s.io/ingress-nginx/kube-webhook-certgen:fake-webhook-version@sha256:123'
            ]
        elif plugin_name == 'kubernetes-dashboard':
            return [
                f'kubernetesui/dashboard:{plugin_version}',
                'kubernetesui/metrics-scraper:fake-metrics-scraper-version'
            ]
        elif plugin_name == 'local-path-provisioner':
            return [
                f'rancher/local-path-provisioner:{plugin_version}'
            ]
        else:
            raise Exception(f"Unsupported plugin {plugin_name!r}")


class FakeCachedManifestResolver(ManifestResolver):
    def __init__(self):
        super().__init__()
        self.registry: Dict[Tuple[str, str], Manifest] = {}

    def resolve(self, plugin_name: str, plugin_version: str) -> Manifest:
        identity = (plugin_name, plugin_version)
        if identity not in self.registry:
            manifest_path = get_default_manifest_path(plugin_name, plugin_version)
            if os.path.exists(manifest_path):
                manifest = super().resolve(plugin_name, plugin_version)
            else:
                manifest = FakeManifest(plugin_name, plugin_version)
            self.registry[identity] = manifest

        return self.registry[identity]


FAKE_CACHED_MANIFEST_RESOLVER = FakeCachedManifestResolver()


class FakeThirdpartyResolver(ThirdpartyResolver):
    def resolve_sha1(self, thirdparty_name: str, version: str) -> str:
        software_mapping: dict = static.GLOBALS['compatibility_map']['software'][thirdparty_name]
        for k8s_version, software_settings in software_mapping.items():
            if thirdparty_name in ('kubeadm', 'kubelet', 'kubectl') and version == k8s_version:
                return software_settings['sha1']
            if thirdparty_name in ('calicoctl', 'crictl') and version == software_settings['version']:
                return software_settings['sha1']
        else:
            return 'fake-sha1'


class NoneManifestsEnrichment(ManifestsEnrichment):
    def __init__(self):
        super().__init__()

    def run(self, tracker: ChangesTracker):
        return


class FakeSynchronization(Synchronization):
    def __init__(self,
                 compatibility: FakeInternalCompatibility,
                 kubernetes_versions: FakeKubernetesVersions,
                 manifest_resolver=FAKE_CACHED_MANIFEST_RESOLVER,
                 manifests_enrichment=NoneManifestsEnrichment(),
                 ):
        super().__init__(
            compatibility,
            kubernetes_versions,
            FakeKubernetesImagesResolver(),
            manifest_resolver,
            FakeThirdpartyResolver(),
            manifests_enrichment,
        )
