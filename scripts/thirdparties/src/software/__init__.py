from typing import Dict, List

from ruamel.yaml import CommentedMap

from kubemarine.core import utils
from ..shell import info
from ..tracker import ChangesTracker

YAML = utils.yaml_structure_preserver()


class CompatibilityMap:
    def __init__(self, tracker: ChangesTracker,
                 map_filename: str, software_names: List[str]):
        """
        Constructs a holder of originally formatted compatibility map.

        :param tracker: ChangesTracker instance
        :param map_filename: file name of internal compatibility map managed by the tool.
        :param software_names: list of software names to keep
        """
        self.tracker = tracker
        self._map_filename = map_filename
        self._resource = f"resources/configurations/compatibility/internal/{map_filename}"
        self._software_names = software_names

        with utils.open_internal(self._resource, 'r') as stream:
            self.compatibility_map: CommentedMap = YAML.load(stream)

        # delete unexpected software
        map_keys = list(self.compatibility_map)
        for key in map_keys:
            if key not in software_names:
                del self.compatibility_map[key]
                self.tracker.unexpected_content = True
                print(f"Deleted {key!r} from {self._map_filename}")

    @property
    def software_names(self) -> List[str]:
        return list(self._software_names)

    @property
    def resource(self) -> str:
        return self._resource

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
                print(f"Deleted '{software_name}.{key}' from {self._map_filename}")

        sorted_map = utils.map_sorted(software_mapping, key=utils.version_key)
        if not (sorted_map is software_mapping):
            self.compatibility_map[software_name] = sorted_map
            print(f"Reordered {software_name!r} in {self._map_filename}")

    def reset_software_settings(self, software_name: str, k8s_version: str, new_settings: Dict[str, str],
                                update=True) -> None:
        """
        Reset software mapping for the specified software name and Kubernetes version to the new provided settings.

        :param software_name: software key
        :param k8s_version: Kubernetes version
        :param new_settings: dictionary with new settings
        :param update: if false, do not update the values for already present settings keys
        """
        software_mapping = self.compatibility_map[software_name]
        if k8s_version in software_mapping:
            software_settings = software_mapping[k8s_version]
        else:
            software_settings = CommentedMap()
            utils.insert_map_sorted(software_mapping, k8s_version, software_settings, key=utils.version_key)
            self.tracker.new(k8s_version)
            print(f"Added '{software_name}.{k8s_version}' to {self._map_filename}")

        # delete unexpected settings
        map_keys = list(software_settings)
        for key in map_keys:
            if key not in new_settings:
                del software_settings[key]
                self.tracker.update(k8s_version, software_name)
                print(f"Deleted '{software_name}.{k8s_version}.{key}' from {self._map_filename}")

        # update the settings only if they are not equal to the new.
        for k, v in new_settings.items():
            if k not in software_settings or (software_settings[k] != v and update):
                software_settings[k] = v
                self.tracker.update(k8s_version, software_name)
                print(f"Changed '{software_name}.{k8s_version}.{k}={v}' in {self._map_filename}")

    def flush(self):
        with utils.open_internal(self._resource, 'w') as stream:
            YAML.dump(self.compatibility_map, stream)

        info(f"Updated {self._map_filename}")
