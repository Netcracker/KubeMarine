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

import collections
from typing import Dict, List, Tuple, Optional, OrderedDict

from ordered_set import OrderedSet

from kubemarine.core import static, utils
from .shell import info


class ChangesTracker:
    def __init__(self, kubernetes_versions: dict):
        self.kubernetes_versions = kubernetes_versions
        self.new_k8s: OrderedSet[str] = OrderedSet()
        self.deleted_k8s: OrderedSet[str] = OrderedSet()
        self.updated_k8s: Dict[str, OrderedSet[str]] = {}
        self.final_messages: List[str] = []
        self.unexpected_content = False

    @property
    def all_k8s_versions(self) -> List[str]:
        return list(self.kubernetes_versions)

    def new(self, k8s_version: str):
        self.new_k8s.add(k8s_version)
        self.updated_k8s.pop(k8s_version, None)

    def delete(self, k8s_version: str):
        self.deleted_k8s.add(k8s_version)

    def update(self, k8s_version: str, software_name: str):
        if k8s_version not in self.new_k8s:
            self.updated_k8s.setdefault(k8s_version, OrderedSet()).add(software_name)

    def is_software_changed(self, k8s_version: str, software_name: str) -> bool:
        return k8s_version in self.new_k8s or software_name in self.updated_k8s.get(k8s_version, set())

    def final_message(self, msg):
        self.final_messages.append(msg)

    def print(self):
        if self.new_k8s:
            info(f"New Kubernetes versions: {', '.join(self.new_k8s)}")
        if self.deleted_k8s:
            info(f"Deleted Kubernetes versions: {', '.join(self.deleted_k8s)}")
        if self.updated_k8s:
            info("Updated Kubernetes compatibility mapping:")
            for k8s_version, software_list in self.updated_k8s.items():
                info(f"\t{k8s_version}: {', '.join(software_list)}")

        requirements = self.get_changed_software_requirements()
        if requirements:
            info("Please check software compatibility and requirements.")

            max_length = max(map(len, (name for software in requirements.values() for name, _ in software)))

            for k8s_version, software_requirements in requirements.items():
                info(f"Kubernetes {k8s_version}:")
                for software_name, req in software_requirements:
                    key = software_name + ': ' + (' ' * (max_length - len(software_name)))
                    info(f"\t{key}{req}")

        if self.unexpected_content:
            info("Deleted unexpected content")

        if self.new_k8s or self.deleted_k8s or self.updated_k8s:
            info("Please do not forget to update documentation/Installation.md")
        elif not self.unexpected_content:
            info("Nothing has changed")

        for msg in self.final_messages:
            info(msg)

    def get_changed_software_requirements(self) -> OrderedDict[str, List[Tuple[str, str]]]:
        software = dict(static.GLOBALS['plugins'])
        software.update(static.GLOBALS['software'])

        requirements: OrderedDict[str, List[Tuple[str, str]]] = collections.OrderedDict()
        for k8s_version in self.all_k8s_versions:
            for software_name, settings_settings in software.items():
                related_software = [software_name]
                if software_name == 'containerd':
                    related_software.append('containerdio')

                if not any(self.is_software_changed(k8s_version, s) for s in related_software):
                    continue

                version = self.kubernetes_versions[k8s_version].get(software_name)
                req = self._get_software_requirements_link(settings_settings, version)
                requirements.setdefault(k8s_version, []).append((software_name, req))

        return requirements

    def _get_software_requirements_link(self, settings_settings: dict, version: Optional[str]):
        minor_version = None if version is None else utils.minor_version(version)

        requirements = settings_settings['requirements']
        if version in requirements:
            req = requirements[version]
        elif minor_version in requirements:
            req = requirements[minor_version]
        else:
            req = requirements['default']

        return req.format(version=version, minor_version=minor_version)
