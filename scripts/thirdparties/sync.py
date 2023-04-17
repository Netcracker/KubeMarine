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
    tracker = ChangesTracker()

    thirdparties.sync(tracker, compatibility_map)
    packages.sync(tracker, compatibility_map)
    kubernetes_images.sync(tracker, compatibility_map)
    plugins.sync(tracker, compatibility_map, refresh_manifests=args.refresh_manifests)

    kubernetes_versions.sync()

    return tracker


if __name__ == '__main__':
    if platform.system() != 'Linux':
        fatal("The tool can be run only on Linux.")

    parser = argparse.ArgumentParser(description="Tool to synchronize thirdparties compatibility mappings")

    parser.add_argument('--refresh-manifests',
                        action='store_true',
                        help='Always download and actualize plugin manifests')

    tracker = sync(parser.parse_args())
    static.reload()

    changed_k8s = list(tracker.new_k8s)
    changed_k8s += list(tracker.updated_k8s)
    for k8s_version in changed_k8s:
        for plugin_name in plugins.PLUGINS:
            if k8s_version in tracker.new_k8s or plugin_name in tracker.updated_k8s[k8s_version]:
                plugins.try_manifest_enrichment(k8s_version, plugin_name)

    tracker.print()
