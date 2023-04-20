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
from typing import List, Tuple, Dict

from kubemarine import thirdparties
from kubemarine.core import utils
from ..shell import curl, TEMP_FILE, SYNC_CACHE
from ..tracker import ChangesTracker
from . import SoftwareType, InternalCompatibility


class ThirdpartyResolver:
    def resolve_sha1(self, thirdparty_name: str, version: str) -> str:
        destination = get_destination(thirdparty_name)
        thirdparty_local_path = resolve_local_path(destination, version)

        print(f"Calculating sha1 for {os.path.basename(thirdparty_local_path)}")
        return utils.get_local_file_sha1(thirdparty_local_path)


class Thirdparties(SoftwareType):
    def __init__(self, compatibility: InternalCompatibility, thirdparty_resolver: ThirdpartyResolver):
        super().__init__(compatibility)
        self.thirdparty_resolver = thirdparty_resolver

    def sync(self, tracker: ChangesTracker):
        """
        Download, calculate sha1 and actualize compatibility_map of all third-parties.
        # TODO if crictl version is changed, it is necessary to write patch that will reinstall corresponding thirdparty.
        """
        thirdparties = ['kubeadm', 'kubelet', 'kubectl', 'calicoctl', 'crictl']
        kubernetes_versions = tracker.kubernetes_versions
        k8s_versions = tracker.all_k8s_versions
        thirdparties_sha1 = calculate_sha1(self.thirdparty_resolver, kubernetes_versions, thirdparties)

        compatibility_map = self.compatibility.load(tracker, "thirdparties.yaml", thirdparties)
        for thirdparty_name in thirdparties:
            compatibility_map.prepare_software_mapping(thirdparty_name, k8s_versions)

            for k8s_version in k8s_versions:
                version = get_version(kubernetes_versions, k8s_version, thirdparty_name)
                sha1 = thirdparties_sha1[(thirdparty_name, version)]

                new_settings = {}
                if thirdparty_name not in ('kubeadm', 'kubelet', 'kubectl'):
                    new_settings['version'] = version

                new_settings['sha1'] = sha1
                compatibility_map.reset_software_settings(thirdparty_name, k8s_version, new_settings)

        self.compatibility.store(compatibility_map)


def get_version(kubernetes_versions: dict, k8s_version: str, thirdparty_name: str) -> str:
    if thirdparty_name in ('kubeadm', 'kubelet', 'kubectl'):
        return k8s_version
    elif thirdparty_name == 'calicoctl':
        return kubernetes_versions[k8s_version]['calico']
    elif thirdparty_name == 'crictl':
        return kubernetes_versions[k8s_version][thirdparty_name]
    else:
        raise Exception(f"Unsupported thirdparty {thirdparty_name!r}")


def get_destination(thirdparty_name: str) -> str:
    if thirdparty_name in ('kubeadm', 'kubelet', 'kubectl', 'calicoctl'):
        return f'/usr/bin/{thirdparty_name}'
    elif thirdparty_name == 'crictl':
        return '/usr/bin/crictl.tar.gz'
    else:
        raise Exception(f"Unsupported thirdparty {thirdparty_name!r}")


def resolve_local_path(destination: str, version: str) -> str:
    filename = f"{destination.split('/')[-1]}-{version}"
    target_file = os.path.join(SYNC_CACHE, filename)
    if os.path.exists(target_file):
        return target_file

    source = thirdparties.get_default_thirdparty_source(destination, version, in_public=True)

    print(f"Downloading thirdparty {destination} of version {version} from {source}")
    curl(source, TEMP_FILE)
    os.rename(TEMP_FILE, target_file)

    return target_file


def calculate_sha1(thirdparty_resolver: ThirdpartyResolver, kubernetes_versions: dict, thirdparties: List[str]) \
        -> Dict[Tuple[str, str], str]:
    thirdparties_sha1 = {}
    for thirdparty_name in thirdparties:
        for k8s_version in kubernetes_versions:
            version = get_version(kubernetes_versions, k8s_version, thirdparty_name)
            thirdparty_identity = (thirdparty_name, version)
            if thirdparty_identity not in thirdparties_sha1:
                thirdparties_sha1[thirdparty_identity] = thirdparty_resolver.resolve_sha1(thirdparty_name, version)

    return thirdparties_sha1
