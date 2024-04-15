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

from copy import deepcopy
from typing import Dict

from ruamel.yaml import CommentedMap

from kubemarine.core import utils, static
from .shell import info, run

# pylint: disable=bad-builtin

YAML = utils.yaml_structure_preserver()
RESOURCE_PATH = utils.get_internal_resource_path("resources/configurations/compatibility/kubernetes_versions.yaml")


class KubernetesVersions:
    def __init__(self) -> None:
        with utils.open_internal(RESOURCE_PATH) as stream:
            self._kubernetes_versions = YAML.load(stream)

        self._validate_mapping()

    @property
    def compatibility_map(self) -> Dict[str, Dict[str, str]]:
        return deepcopy(self._kubernetes_versions['compatibility_map'])

    def sync(self) -> None:
        k8s_versions = self._kubernetes_versions['kubernetes_versions']
        k8s_versions = utils.map_sorted(k8s_versions, key=utils.minor_version_key)
        self._kubernetes_versions['kubernetes_versions'] = k8s_versions

        minor_versions = set()
        for k8s_version in self._kubernetes_versions['compatibility_map']:
            minor_version = utils.minor_version(k8s_version)
            minor_versions.add(minor_version)
            if minor_version not in k8s_versions:
                utils.insert_map_sorted(k8s_versions, minor_version, CommentedMap({'supported': True}),
                                        key=utils.minor_version_key)

        for key in list(k8s_versions):
            if key not in minor_versions:
                del k8s_versions[key]

    def store(self) -> None:
        with utils.open_internal(RESOURCE_PATH, 'w') as stream:
            YAML.dump(self._kubernetes_versions, stream)

        run(['git', 'add', RESOURCE_PATH])
        info(f"Updated kubernetes_versions.yaml")

    def _validate_mapping(self) -> None:
        mandatory_fields = set(static.GLOBALS['plugins'])
        mandatory_fields.update(['crictl'])
        optional_fields = {
            'webhook', 'metrics-scraper', 'busybox',
            # To support custom pause image, it is necessary to implement software upgrade patch.
            # 'pause',
        }

        compatibility_map = self._kubernetes_versions['compatibility_map']
        unique_version_keys = set()
        for k8s_version, software in compatibility_map.items():
            version_key = utils.version_key(k8s_version)
            if version_key in unique_version_keys:
                raise Exception(f"Only one release or release candidate is supported "
                                f"for v{'.'.join(map(str, version_key))}")

            unique_version_keys.add(version_key)
            missing_mandatory = mandatory_fields - set(software)
            if missing_mandatory:
                raise Exception(f"Missing {', '.join(map(repr, missing_mandatory))} software "
                                f"for Kubernetes {k8s_version} in kubernetes_versions.yaml")

            unexpected_optional = set(software) - mandatory_fields - optional_fields
            if unexpected_optional:
                raise Exception(f"Unexpected {', '.join(map(repr, unexpected_optional))} software "
                                f"for Kubernetes {k8s_version} in kubernetes_versions.yaml. "
                                f"Allowed optional software: {', '.join(map(repr, optional_fields))}.")
