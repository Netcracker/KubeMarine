import os
import sys

# Ensure to take Kubemarine modules from the project root.
# !!! This should be a very first line of the script !!!
ROOT = os.path.abspath(f"{__file__}/../../..")
sys.path.insert(0, ROOT)

import argparse
import platform

from kubemarine.core import static
from src.compatibility import KubernetesVersions
from src.shell import fatal
from src.software import kubernetes_images
from src.software import packages
from src.software import plugins
from src.software import thirdparties
from src.tracker import ChangesTracker


def sync(args: argparse.Namespace) -> ChangesTracker:
    kubernetes_versions = KubernetesVersions()
    compatibility_map = kubernetes_versions.compatibility_map
    tracker = ChangesTracker(compatibility_map)

    thirdparties.sync(tracker)
    packages.sync(tracker)
    kubernetes_images.sync(tracker)
    plugins.sync(tracker, refresh_manifests=args.refresh_manifests)

    kubernetes_versions.sync()

    static.reload()
    try_manifest_enrichment(tracker, force=args.enrich_manifests)

    return tracker


def try_manifest_enrichment(tracker: ChangesTracker, force: bool) -> None:
    for k8s_version in tracker.all_k8s_versions:
        for plugin_name in list(static.GLOBALS['plugins']):
            if force or tracker.is_software_changed(k8s_version, plugin_name):
                plugins.try_manifest_enrichment(k8s_version, plugin_name)


if __name__ == '__main__':
    if platform.system() != 'Linux':
        fatal("The tool can be run only on Linux.")

    parser = argparse.ArgumentParser(description="Tool to synchronize thirdparties compatibility mappings")

    parser.add_argument('--refresh-manifests',
                        action='store_true',
                        help='Always download and actualize plugin manifests')

    parser.add_argument('--enrich-manifests',
                        action='store_true',
                        help='Run enrichment of all plugin manifests for all Kubernetes versions')

    tracker = sync(parser.parse_args())
    tracker.print()
