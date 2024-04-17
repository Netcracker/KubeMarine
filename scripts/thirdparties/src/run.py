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
from typing import List

from kubemarine.core import static
from .compatibility import KubernetesVersions
from .software import InternalCompatibility, UpgradeConfig, CompatibilityMap, SoftwareType
from .software.kubernetes_images import KubernetesImagesResolver, KubernetesImages
from .software.packages import Packages
from .software.plugins import ManifestResolver, Plugins, ManifestsEnrichment
from .software.thirdparties import ThirdpartyResolver, Thirdparties
from .tracker import SummaryTracker

# pylint: disable=bad-builtin


class Synchronization:
    def __init__(self,
                 compatibility: InternalCompatibility,
                 kubernetes_versions: KubernetesVersions,
                 images_resolver: KubernetesImagesResolver,
                 manifest_resolver: ManifestResolver,
                 thirdparty_resolver: ThirdpartyResolver,
                 manifests_enrichment: ManifestsEnrichment,
                 upgrade_config: UpgradeConfig,
                 ):
        self.compatibility = compatibility
        self.kubernetes_versions = kubernetes_versions
        self.images_resolver = images_resolver
        self.manifest_resolver = manifest_resolver
        self.thirdparty_resolver = thirdparty_resolver
        self.manifests_enrichment = manifests_enrichment
        self.upgrade_config = upgrade_config

    def run(self) -> SummaryTracker:
        tracker = SummaryTracker(self.kubernetes_versions.compatibility_map)

        software: List[SoftwareType] = [
            Thirdparties(self.compatibility, self.upgrade_config, self.thirdparty_resolver),
            Packages(self.compatibility, self.upgrade_config),
            KubernetesImages(self.compatibility, self.upgrade_config, self.images_resolver),
            Plugins(self.compatibility, self.upgrade_config, self.manifest_resolver),
        ]

        # Change all configs in memory
        self.upgrade_config.prepare(tracker, [software_type.name for software_type in software])

        compatibility_maps: List[CompatibilityMap] = []
        for software_type in software:
            compatibility_maps.append(software_type.sync(tracker))

        self.kubernetes_versions.sync()

        # Flush all configs
        for compatibility_map in compatibility_maps:
            self.compatibility.store(compatibility_map)

        self.upgrade_config.store()
        self.kubernetes_versions.store()

        # To run fake enrichment, we need to reload all compatibility maps.
        static.reload()
        self.manifests_enrichment.run(tracker)

        tracker.print()
        return tracker
