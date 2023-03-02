import io
from typing import Dict, Callable, Optional, List

import ruamel.yaml
import os
from abc import ABC, abstractmethod

from kubemarine import plugins
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster

EnrichmentFunction = Callable[[KubernetesCluster, str, dict], Optional[dict]]


class Processor(ABC):
    def __init__(self, cluster: KubernetesCluster, inventory: dict,
                 plugin_name: str, original_yaml_path: str, destination_name: str):
        """
        :param cluster: cluster object
        :param inventory: inventory of the cluster
        :param plugin_name: name of plugin-owner
        :param original_yaml_path: path to original manifest
        :param destination_name: destination manifest file name
        """
        self.cluster = cluster
        self.log = cluster.log
        self.inventory = inventory
        self.plugin_name = plugin_name
        self.original_yaml_path = original_yaml_path
        self.destination_name = destination_name

    def get_known_objects(self) -> List[str]:
        """
        :return: list of expected objects in original manifest
        """
        return []

    @abstractmethod
    def get_enrichment_functions(self) -> Dict[str, EnrichmentFunction]:
        """
        :return: name of objects and enrichment methods mapping
        """
        pass

    def validate_inventory(self) -> None:
        """
        # Check if original YAML exists
        """
        config = {
            "source": self.original_yaml_path
        }
        original_yaml_path, _ = plugins.get_source_absolute_pattern(config)
        if not os.path.isfile(original_yaml_path):
            raise Exception(f"Cannot find original manifest {original_yaml_path} for {self.plugin_name!r} plugin")

    def validate_original(self, obj_list: Dict[str, dict]) -> None:
        """
        The method implements default validations for manifest objects

        :param obj_list: objects for validation
        """
        known_objects = self.get_known_objects()

        # check if there are new objects
        for key in obj_list.keys():
            if key not in known_objects:
                self.log.verbose(f"The current version of original yaml has a new object: {key}")

        # check if known objects were excluded
        for key in known_objects:
            if key not in obj_list.keys():
                self.log.verbose(f"The current version of original yaml does not include"
                                 f"the following object: {key}")

    # TODO: implement method for validation after enrichment
    def validate_result(self, obj_list: Dict[str, dict]):
        """
        Some validation inside the objects.
        """
        return

    def apply(self):
        """
        The method implements full processing for the plugin main manifest.
        """
        destination = '/etc/kubernetes/%s' % self.destination_name

        # create config for plugin module
        config = {
            "source": self.original_yaml_path,
            "destination": destination,
            "do_render": False
        }

        # get original YAML and parse it into dict of objects
        original_yaml_path, _ = plugins.get_source_absolute_pattern(config)
        obj_list = self._load_multiple_yaml(original_yaml_path)

        self.validate_original(obj_list)

        patched_list = []
        excluded_list = []

        # enrich objects one by one
        enrichment_functions = self.get_enrichment_functions()
        for key in enrichment_functions.keys():
            if key not in obj_list.keys():
                continue

            target_yaml = enrichment_functions[key](self.cluster, key, obj_list[key])
            if target_yaml is None:
                obj_list.pop(key)
                excluded_list.append(key)
                self.log.verbose(f"The {key} has been excluded from result")
            else:
                patched_list.append(key)
                obj_list[key] = target_yaml

        self.log.verbose(f"The total number of patched objects is {len(patched_list)} "
                         f"the objects are the following: {patched_list}")
        self.log.verbose(f"The total number of excluded objects is {len(excluded_list)} "
                         f"the objects are the following: {excluded_list}")

        self.validate_result(obj_list)
        enriched_manifest = self._dump_multiple_yaml(obj_list)
        utils.dump_file(self.cluster, enriched_manifest, self.destination_name)
        config['source'] = io.StringIO(enriched_manifest)

        self.log.debug(f"Uploading manifest enriched from {original_yaml_path} for {self.plugin_name!r} plugin...")
        self.log.debug("\tDestination: %s" % destination)

        plugins.apply_source(self.cluster, config)

    def _load_multiple_yaml(self, filepath) -> dict:
        """
        The method implements the parse YAML file that includes several YAMLs inside
        :param filepath: Path to file that should be parsed
        :return: dictionary with the 'kind' and 'name' of object as 'key' and whole YAML structure as 'value'
        """
        yaml = ruamel.yaml.YAML()
        yaml_dict = {}
        try:
            with utils.open_utf8(filepath, 'r') as stream:
                source_yamls = yaml.load_all(stream)
                for source_yaml in source_yamls:
                    if source_yaml:
                        yaml_key = f"{source_yaml['kind']}_{source_yaml['metadata']['name']}"
                        # check if there is no duplication
                        if yaml_key not in yaml_dict:
                            yaml_dict[yaml_key] = source_yaml
                        else:
                            raise Exception(
                                f"ERROR: the {yaml_key} object is duplicated, please verify the original yaml")
            return yaml_dict
        except Exception as exc:
            raise Exception(f"Failed to load {filepath} for {self.plugin_name!r} plugin") from exc

    def _dump_multiple_yaml(self, multi_yaml: dict) -> str:
        """
        The method implements the dumping some dictionary to the string that includes several YAMLs inside
        :param multi_yaml: dictionary with the 'kind' and 'name' of object as 'key' and whole YAML structure as 'value'
        """
        yaml = ruamel.yaml.YAML()

        with io.StringIO() as stream:
            yaml.dump_all(multi_yaml.values(), stream)
            result = stream.getvalue()

        return result
