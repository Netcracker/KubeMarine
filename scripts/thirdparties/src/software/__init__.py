import os.path
from abc import ABC, abstractmethod
from typing import Dict, List

from ruamel.yaml import CommentedMap

from kubemarine.core import utils
from ..shell import info, run
from ..tracker import ChangesTracker

YAML = utils.yaml_structure_preserver()


class CompatibilityMap:
    def __init__(self, tracker: ChangesTracker, filename: str, software_names: List[str]):
        """
        Constructs a holder of originally formatted compatibility map.

        :param tracker: ChangesTracker instance
        :param map_filename: file name of internal compatibility map managed by the tool.
        :param software_names: list of software names to keep
        """
        self.tracker = tracker
        self._resource = f"resources/configurations/compatibility/internal/{filename}"

        with utils.open_internal(self.resource_path, 'r') as stream:
            self.compatibility_map: CommentedMap = YAML.load(stream)

        # delete unexpected software
        map_keys = list(self.compatibility_map)
        for key in map_keys:
            if key not in software_names:
                del self.compatibility_map[key]
                self.tracker.unexpected_content = True
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
                self.tracker.delete(key)
                print(f"Deleted '{software_name}.{key}' from {self.name}")

        sorted_map = utils.map_sorted(software_mapping, key=utils.version_key)
        if not (sorted_map is software_mapping):
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
    def load(self, tracker: ChangesTracker, filename: str, software_names: List[str]) -> CompatibilityMap:
        return CompatibilityMap(tracker, filename, software_names)

    def store(self, compatibility_map: CompatibilityMap):
        with utils.open_internal(compatibility_map.resource_path, 'w') as stream:
            YAML.dump(compatibility_map.compatibility_map, stream)

        run(['git', 'add', compatibility_map.resource_path])
        info(f"Updated {compatibility_map.name}")


class SoftwareType(ABC):
    def __init__(self, compatibility: InternalCompatibility):
        self.compatibility = compatibility

    @abstractmethod
    def sync(self, tracker: ChangesTracker):
        pass
