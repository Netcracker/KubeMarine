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

import os
import sys

# pylint: disable=bad-builtin,wrong-import-position

# Ensure to take Kubemarine modules from the project root.
# !!! This should be a very first line of the script !!!
ROOT = os.path.abspath(f"{__file__}/../../..")
sys.path.insert(0, ROOT)

import argparse
import platform

from src.compatibility import KubernetesVersions
from src.run import Synchronization
from src.shell import fatal
from src.software import InternalCompatibility, UpgradeConfig
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
        UpgradeConfig(),
    ).run()
