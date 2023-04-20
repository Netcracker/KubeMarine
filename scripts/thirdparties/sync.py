import os
import sys

# Ensure to take Kubemarine modules from the project root.
# !!! This should be a very first line of the script !!!
ROOT = os.path.abspath(f"{__file__}/../../..")
sys.path.insert(0, ROOT)

import argparse
import platform

from src.compatibility import KubernetesVersions
from src.run import Synchronization
from src.shell import fatal
from src.software import InternalCompatibility
from src.software.kubernetes_images import KubernetesImagesResolver
from src.software.plugins import ManifestResolver, ManifestsEnrichment
from src.software.thirdparties import ThirdpartyResolver

if __name__ == '__main__':
    if platform.system() != 'Linux':
        fatal("The tool can be run only on Linux.")

    parser = argparse.ArgumentParser(description="Tool to synchronize thirdparties compatibility mappings")

    parser.add_argument('--refresh-manifests',
                        action='store_true',
                        help='Always download and actualize plugin manifests')

    args = parser.parse_args()
    Synchronization(
        InternalCompatibility(),
        KubernetesVersions(),
        KubernetesImagesResolver(),
        ManifestResolver(refresh=args.refresh_manifests),
        ThirdpartyResolver(),
        ManifestsEnrichment(),
    ).run()
