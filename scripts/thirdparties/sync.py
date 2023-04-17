import os
import sys

# Ensure to take Kubemarine modules from the project root.
# !!! This should be a very first line of the script !!!
ROOT = os.path.abspath(f"{__file__}/../../..")
sys.path.insert(0, ROOT)

import argparse
import platform

from src.compatibility import KubernetesVersions
from src.shell import fatal
from src.software import kubernetes_images
from src.software import packages
from src.software import plugins
from src.software import thirdparties
from src.tracker import ChangesTracker

if platform.system() != 'Linux':
    fatal("The tool can be run only on Linux.")

parser = argparse.ArgumentParser(description="Tool to synchronize thirdparties compatibility mappings")

parser.add_argument('--refresh-manifests',
                    action='store_true',
                    help='Always download and actualize plugin manifests')

args = parser.parse_args()

kubernetes_versions = KubernetesVersions()
compatibility_map = kubernetes_versions.compatibility_map
tracker = ChangesTracker()

thirdparties.sync(tracker, compatibility_map)
packages.sync(tracker, compatibility_map)
kubernetes_images.sync(tracker, compatibility_map)
plugins.sync(tracker, compatibility_map, refresh_manifests=args.refresh_manifests)

kubernetes_versions.sync()
tracker.print()
