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
import os
from copy import deepcopy
from typing import List, Dict, Tuple, Optional

import yaml
from ruamel.yaml import CommentedMap

from kubemarine.core import static, utils
from kubemarine.plugins.manifest import Manifest, get_default_manifest_path, Identity
from scripts.thirdparties.src.compatibility import KubernetesVersions
from scripts.thirdparties.src.run import Synchronization
from scripts.thirdparties.src.software import InternalCompatibility, CompatibilityMap, UpgradeConfig
from scripts.thirdparties.src.software.kubernetes_images import KubernetesImagesResolver
from scripts.thirdparties.src.software.plugins import ManifestResolver, ManifestsEnrichment
from scripts.thirdparties.src.software.thirdparties import ThirdpartyResolver
from scripts.thirdparties.src.tracker import SummaryTracker


class FakeInternalCompatibility(InternalCompatibility):
    def __init__(self):
        self.stored = {}

    def store(self, compatibility_map: CompatibilityMap):
        self.stored[compatibility_map.name] = deepcopy(compatibility_map.compatibility_map)


class FakeKubernetesVersions(KubernetesVersions):
    def __init__(self):
        super().__init__()
        self.stored: Optional[CommentedMap] = None

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
    def __init__(self, manifest_identity: Identity, plugin_version: str):
        super().__init__(manifest_identity, io.StringIO())
        self.images = self._stub_images(manifest_identity, plugin_version)

    def get_all_container_images(self) -> List[str]:
        return self.images

    def _stub_images(self, manifest_identity: Identity, plugin_version: str) -> List[str]:
        if manifest_identity == Identity('calico'):
            return [
                f'docker.io/calico/node:{plugin_version}',
                f'docker.io/calico/cni:{plugin_version}',
                f'docker.io/calico/kube-controllers:{plugin_version}',
                f'docker.io/calico/typha:{plugin_version}'
            ]
        elif manifest_identity == Identity('calico', 'apiserver'):
            return [
                f'calico/apiserver:{plugin_version}',
            ]
        elif manifest_identity == Identity('nginx-ingress-controller'):
            return [
                f'registry.k8s.io/ingress-nginx/controller:{plugin_version}@sha256:123',
                'registry.k8s.io/ingress-nginx/kube-webhook-certgen:fake-webhook-version@sha256:123'
            ]
        elif manifest_identity == Identity('kubernetes-dashboard'):
            return [
                f'kubernetesui/dashboard:{plugin_version}',
                'kubernetesui/metrics-scraper:fake-metrics-scraper-version'
            ]
        elif manifest_identity == Identity('local-path-provisioner'):
            return [
                f'rancher/local-path-provisioner:{plugin_version}'
            ]
        else:
            raise Exception(f"Unsupported manifest {manifest_identity.name!r}")


class FakeCachedManifestResolver(ManifestResolver):
    def __init__(self):
        super().__init__()
        self.registry: Dict[Tuple[Identity, str], Manifest] = {}

    def _resolve(self, manifest_identity: Identity, plugin_version: str) -> Manifest:
        identity = (manifest_identity, plugin_version)
        if identity not in self.registry:
            manifest_path = get_default_manifest_path(manifest_identity, plugin_version)
            if os.path.exists(manifest_path):
                manifest = super()._resolve(manifest_identity, plugin_version)
            else:
                manifest = FakeManifest(manifest_identity, plugin_version)
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

    def run(self, tracker: SummaryTracker) -> None:
        return


class FakeUpgradeConfig(UpgradeConfig):
    def __init__(self):
        super().__init__()
        self.stored: Optional[CommentedMap] = None

    def store(self):
        self.stored = deepcopy(self.config)


class FakeSynchronization(Synchronization):
    def __init__(self,
                 compatibility: FakeInternalCompatibility,
                 kubernetes_versions: FakeKubernetesVersions,
                 manifest_resolver=FAKE_CACHED_MANIFEST_RESOLVER,
                 manifests_enrichment=NoneManifestsEnrichment(),
                 upgrade_config=FakeUpgradeConfig(),
                 ):
        super().__init__(
            compatibility,
            kubernetes_versions,
            FakeKubernetesImagesResolver(),
            manifest_resolver,
            FakeThirdpartyResolver(),
            manifests_enrichment,
            upgrade_config,
        )
