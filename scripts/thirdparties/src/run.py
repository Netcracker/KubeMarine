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

    def run(self) -> None:
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
