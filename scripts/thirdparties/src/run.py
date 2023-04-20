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

from kubemarine.core import static
from .compatibility import KubernetesVersions
from .software import InternalCompatibility
from .software.kubernetes_images import KubernetesImagesResolver, KubernetesImages
from .software.packages import Packages
from .software.plugins import ManifestResolver, Plugins, ManifestsEnrichment
from .software.thirdparties import ThirdpartyResolver, Thirdparties
from .tracker import ChangesTracker


class Synchronization:
    def __init__(self,
                 compatibility: InternalCompatibility,
                 kubernetes_versions: KubernetesVersions,
                 images_resolver: KubernetesImagesResolver,
                 manifest_resolver: ManifestResolver,
                 thirdparty_resolver: ThirdpartyResolver,
                 manifests_enrichment: ManifestsEnrichment,
                 ):
        self.compatibility = compatibility
        self.kubernetes_versions = kubernetes_versions
        self.images_resolver = images_resolver
        self.manifest_resolver = manifest_resolver
        self.thirdparty_resolver = thirdparty_resolver
        self.manifests_enrichment = manifests_enrichment

    def run(self) -> ChangesTracker:
        compatibility_map = self.kubernetes_versions.compatibility_map
        tracker = ChangesTracker(compatibility_map)

        software = [
            Thirdparties(self.compatibility, self.thirdparty_resolver),
            Packages(self.compatibility),
            KubernetesImages(self.compatibility, self.images_resolver),
            Plugins(self.compatibility, self.manifest_resolver),
        ]
        for software_type in software:
            software_type.sync(tracker)

        self.kubernetes_versions.sync()

        static.reload()
        self.manifests_enrichment.run(tracker)

        tracker.print()
        return tracker
