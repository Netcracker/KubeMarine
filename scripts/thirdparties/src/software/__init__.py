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

import os.path
from abc import ABC, abstractmethod
from typing import Dict, List, Set

from ruamel.yaml import CommentedMap

from kubemarine.core import utils
from kubemarine.procedures import migrate_kubemarine
from ..shell import info, run
from ..tracker import SummaryTracker, ChangesTracker

# pylint: disable=bad-builtin

YAML = utils.yaml_structure_preserver()
SOFTWARE_UPGRADE_PATH = migrate_kubemarine.SOFTWARE_UPGRADE_PATH


class CompatibilityMap:
    def __init__(self, tracker: ChangesTracker, filename: str):
        """
        Constructs a holder of originally formatted compatibility map.

        :param tracker: ChangesTracker instance
        :param filename: file name of internal compatibility map managed by the tool.
        """
        self.tracker = tracker
        self._resource = f"resources/configurations/compatibility/internal/{filename}"

        with utils.open_internal(self.resource_path, 'r') as stream:
            self.compatibility_map: CommentedMap = YAML.load(stream)

    def prepare(self, summary_tracker: SummaryTracker, software_names: List[str]) -> None:
        """
        Delete unexpected software.

        :param summary_tracker: SummaryTracker instance
        :param software_names: list of software names to keep
        """
        map_keys = list(self.compatibility_map)
        for key in map_keys:
            if key not in software_names:
                del self.compatibility_map[key]
                summary_tracker.deleted_unexpected_content = True
                print(f"Deleted {key!r} from {self.name}")

    @property
    def resource_path(self) -> str:
        return utils.get_internal_resource_path(self._resource)

    @property
    def resource(self) -> str:
        return self._resource

    @property
    def name(self) -> str:
        return os.path.basename(self._resource)

    def prepare_software_mapping(self, software_name: str, k8s_versions: List[str]) -> None:
        """
        Prepares software mapping for each Kubernetes version for update.
        Kubernetes version that are not listed in the 'k8s_versions' param, are removed.
        Existing versions are sorted if necessary.

        :param software_name: software key
        :param k8s_versions: list of Kubernetes version to keep
        :return: prepared k8s -> settings mapping.
        """
        software_mapping = self.compatibility_map.setdefault(software_name, CommentedMap())

        # delete not longer managed Kubernetes versions
        map_keys = list(software_mapping)
        for key in map_keys:
            if key not in k8s_versions:
                del software_mapping[key]
                self.tracker.delete(key, software_name)
                print(f"Deleted '{software_name}.{key}' from {self.name}")

        sorted_map = utils.map_sorted(software_mapping, key=utils.version_key)
        if sorted_map is not software_mapping:
            self.compatibility_map[software_name] = sorted_map
            print(f"Reordered {software_name!r} in {self.name}")

    def reset_software_settings(self, software_name: str, k8s_version: str, new_settings: Dict[str, str]) -> None:
        """
        Reset software mapping for the specified software name and Kubernetes version to the new provided settings.

        :param software_name: software key
        :param k8s_version: Kubernetes version
        :param new_settings: dictionary with new settings
        """
        software_mapping = self.compatibility_map[software_name]
        if k8s_version in software_mapping:
            software_settings = software_mapping[k8s_version]
        else:
            software_settings = CommentedMap()
            utils.insert_map_sorted(software_mapping, k8s_version, software_settings, key=utils.version_key)
            self.tracker.new(k8s_version)
            print(f"Added '{software_name}.{k8s_version}' to {self.name}")

        # delete unexpected settings
        map_keys = list(software_settings)
        for key in map_keys:
            if key not in new_settings:
                del software_settings[key]
                self.tracker.update(k8s_version, software_name)
                print(f"Deleted '{software_name}.{k8s_version}.{key}' from {self.name}")

        # update the settings only if they are not equal to the new.
        for k, v in new_settings.items():
            if k not in software_settings or software_settings[k] != v:
                software_settings[k] = v
                self.tracker.update(k8s_version, software_name)
                print(f"Changed '{software_name}.{k8s_version}.{k}={v}' in {self.name}")


class InternalCompatibility:
    def load(self, tracker: ChangesTracker, filename: str) -> CompatibilityMap:
        return CompatibilityMap(tracker, filename)

    def store(self, compatibility_map: CompatibilityMap) -> None:
        with utils.open_internal(compatibility_map.resource_path, 'w') as stream:
            YAML.dump(compatibility_map.compatibility_map, stream)

        run(['git', 'add', compatibility_map.resource_path])
        info(f"Updated {compatibility_map.name}")


class UpgradeConfig:
    def __init__(self) -> None:
        with utils.open_internal(SOFTWARE_UPGRADE_PATH) as stream:
            self.config: CommentedMap = YAML.load(stream)

    @property
    def name(self) -> str:
        return os.path.basename(SOFTWARE_UPGRADE_PATH)

    def prepare(self, tracker: SummaryTracker, software_types: List[str]) -> None:
        """
        Create stubs for known software types and delete unexpected software types.

        :param tracker: SummaryTracker instance
        :param software_types: list of software types to keep
        """
        for software_type in software_types:
            if software_type not in self.config:
                self.config[software_type] = CommentedMap()

        map_keys = list(self.config)
        for key in map_keys:
            if key not in software_types:
                del self.config[key]
                tracker.deleted_unexpected_content = True
                print(f"Deleted {key!r} from {self.name}")

    def store(self) -> None:
        with utils.open_internal(SOFTWARE_UPGRADE_PATH, 'w') as stream:
            YAML.dump(self.config, stream)

        run(['git', 'add', SOFTWARE_UPGRADE_PATH])
        info(f"Updated {os.path.basename(SOFTWARE_UPGRADE_PATH)}")


class UpgradeSoftware(ChangesTracker):
    def __init__(self, upgrade_config: UpgradeConfig, software_type: str, software_names: List[str]):
        self.upgrade_config = upgrade_config
        self.software_type = software_type
        self.software_names = software_names
        if software_names:
            self.config: CommentedMap = upgrade_config.config[software_type]
        else:
            self.config = upgrade_config.config.pop(software_type)
        self._new_k8s: Set[str] = set()

    def prepare(self, summary_tracker: SummaryTracker) -> None:
        """
        Create stubs for known software and delete unexpected software.

        :param summary_tracker: SummaryTracker instance
        """
        for software_name in self.software_names:
            if software_name not in self.config:
                self.config[software_name] = []

        map_keys = list(self.config)
        for key in map_keys:
            if key not in self.software_names:
                del self.config[key]
                summary_tracker.deleted_unexpected_content = True
                print(f"Deleted {self.software_type}.{key} from {self.upgrade_config.name}")

    def new(self, k8s_version: str) -> None:
        self._new_k8s.add(k8s_version)

    def delete(self, k8s_version: str, software_name: str) -> None:
        if software_name not in self.software_names:
            return
        k8s_versions: list = self.config[software_name]
        if k8s_version in k8s_versions:
            k8s_versions.remove(k8s_version)

    def update(self, k8s_version: str, software_name: str) -> None:
        if k8s_version in self._new_k8s:
            return
        if software_name not in self.software_names:
            raise Exception(f"Unsupported upgrade of software {software_name!r}.")
        k8s_versions: list = self.config[software_name]
        if k8s_version not in k8s_versions:
            k8s_versions.append(k8s_version)
            k8s_versions.sort(key=utils.version_key)
            info(f'Software {software_name!r} is scheduled for upgrade for Kubernetes {k8s_version}')


class SoftwareType(ABC):
    def __init__(self, compatibility: InternalCompatibility, upgrade_config: UpgradeConfig):
        self.compatibility = compatibility
        self.upgrade_config = upgrade_config

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def sync(self, summary_tracker: SummaryTracker) -> CompatibilityMap:
        pass
