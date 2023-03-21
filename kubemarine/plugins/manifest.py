# Copyright 2021-2022 NetCracker Technology Corporation
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

import io
from typing import Callable, Optional, List

import ruamel.yaml
import os
from abc import ABC, abstractmethod

from ordered_set import OrderedSet

from kubemarine import plugins
from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster


class Manifest:
    def __init__(self, logger: log.EnhancedLogger, filepath: str):
        self.logger = logger
        self._patched = OrderedSet()
        self._excluded = OrderedSet()
        self._included = OrderedSet()
        self._obj_list = self._load(filepath)

    def obj_key(self, obj: dict) -> str:
        return f"{obj['kind']}_{obj['metadata']['name']}"

    def all_obj_keys(self) -> List[str]:
        return [self.obj_key(obj) for obj in self._obj_list]

    def key_index(self, key: str) -> int:
        for i, obj in enumerate(self._obj_list):
            if self.obj_key(obj) == key:
                return i

        raise ValueError(f"{key} not found")

    def get_obj(self, key: str, *, patch: bool, allow_absent=False) -> Optional[dict]:
        """
        Get manifest object in YAML format for the specified key.
        By default, ensure presence of the object.
        If the object is absent, it may be a sign that we no longer able to fulfill the previous contract.
        Caller methods must explicitly allow absent object when necessary.

        :param key: 'kind' and 'name' of object
        :param patch: boolean value that tells the manifest that the searched object is going to be patched.
        :param allow_absent: if true, do not throw exception if the object by key is absent.
        :return: manifest object
        """
        for obj in self._obj_list:
            if self.obj_key(obj) == key:
                if patch:
                    self._patched.add(key)
                return obj

        if not allow_absent:
            raise ValueError(f"{key} not found")
        return None

    def include(self, index: int, obj: dict):
        self._obj_list.insert(index, obj)
        key = self.obj_key(obj)
        self._included.add(key)
        self.logger.verbose(f"The {key} has been added")

    def exclude(self, key: str):
        del self._obj_list[self.key_index(key)]
        self._excluded.add(key)
        self.logger.verbose(f"The {key} has been excluded from result")

    @property
    def patched(self) -> List[str]:
        return list(self._patched)

    @property
    def included(self) -> List[str]:
        return list(self._included)

    @property
    def excluded(self) -> List[str]:
        return list(self._excluded)

    def dump(self) -> str:
        """
        The method implements the dumping of the list of objects to the string that includes several YAMLs inside
        """
        yaml = ruamel.yaml.YAML()

        with io.StringIO() as stream:
            yaml.dump_all(self._obj_list, stream)
            result = stream.getvalue()

        return result

    def _load(self, filepath: str) -> List[dict]:
        """
        The method implements the parse YAML file that includes several YAMLs inside
        :param filepath: Path to file that should be parsed
        :return: list of original objects to enrich in YAML format.
        """
        yaml = ruamel.yaml.YAML()
        obj_list = []
        with utils.open_utf8(filepath, 'r') as stream:
            source_yamls = yaml.load_all(stream)
            yaml_keys = set()
            for source_yaml in source_yamls:
                if source_yaml is None:
                    continue
                yaml_key = self.obj_key(source_yaml)
                # check if there is no duplication
                if yaml_key in yaml_keys:
                    raise Exception(
                        f"The {yaml_key} object is duplicated, please verify the original yaml")

                yaml_keys.add(yaml_key)
                obj_list.append(source_yaml)

        return obj_list


EnrichmentFunction = Callable[[Manifest], None]


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
        self.log: log.EnhancedLogger = cluster.log
        self.inventory = inventory
        self.plugin_name = plugin_name
        self.original_yaml_path = original_yaml_path
        self.destination_name = destination_name

    def get_known_objects(self) -> List[str]:
        """
        :return: list with the 'kind' and 'name' of expected objects in original manifest
        """
        return []

    @abstractmethod
    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        """
        :return: list of enrichment methods
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

    def validate_original(self, manifest: Manifest) -> None:
        """
        The method implements default validations for manifest objects

        :param manifest: container to operate with manifest objects
        """
        known_objects = self.get_known_objects()

        # check if there are new objects
        for key in manifest.all_obj_keys():
            if key not in known_objects:
                self.log.verbose(f"The current version of original yaml has a new object: {key}")

        # check if known objects were excluded
        for key in known_objects:
            if manifest.get_obj(key, patch=False, allow_absent=True) is None:
                self.log.verbose(f"The current version of original yaml does not include "
                                 f"the following object: {key}")

    # TODO: implement method for validation after enrichment
    def validate_result(self, manifest: Manifest):
        """
        Some validation inside the manifest objects.
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

        # get original YAML and parse it into list of objects
        original_yaml_path, _ = plugins.get_source_absolute_pattern(config)
        try:
            manifest = Manifest(self.log, original_yaml_path)
        except Exception as exc:
            raise Exception(f"Failed to load {original_yaml_path} for {self.plugin_name!r} plugin") from exc

        self.validate_original(manifest)

        # call enrichment functions one by one
        enrichment_functions = self.get_enrichment_functions()
        for fn in enrichment_functions:
            fn(manifest)

        self.log.verbose(f"The total number of patched objects is {len(manifest.patched)} "
                         f"the objects are the following: {manifest.patched}")
        self.log.verbose(f"The total number of added objects is {len(manifest.included)} "
                         f"the objects are the following: {manifest.included}")
        self.log.verbose(f"The total number of excluded objects is {len(manifest.excluded)} "
                         f"the objects are the following: {manifest.excluded}")

        self.validate_result(manifest)
        enriched_manifest = manifest.dump()
        utils.dump_file(self.cluster, enriched_manifest, self.destination_name)
        config['source'] = io.StringIO(enriched_manifest)

        self.log.debug(f"Uploading manifest enriched from {original_yaml_path} for {self.plugin_name!r} plugin...")
        self.log.debug("\tDestination: %s" % destination)

        plugins.apply_source(self.cluster, config)

    def assign_default_pss_labels(self, manifest: Manifest, key: str, profile: str):
        source_yaml = manifest.get_obj(key, patch=True)
        labels: dict = source_yaml['metadata'].setdefault('labels', {})
        labels.update({
            'pod-security.kubernetes.io/enforce': profile,
            'pod-security.kubernetes.io/enforce-version': 'latest',
            'pod-security.kubernetes.io/audit': profile,
            'pod-security.kubernetes.io/audit-version': 'latest',
            'pod-security.kubernetes.io/warn': profile,
            'pod-security.kubernetes.io/warn-version': 'latest',
        })
        self.log.verbose(f"The {key} has been patched in 'metadata.labels' with pss labels for {profile!r} profile")

    def find_container_for_patch(self, manifest: Manifest, key: str,
                                 *,
                                 container_name: str, is_init_container: bool, allow_absent=False) -> (int, dict):
        """
        Find container according to the search criteria.

        :param manifest: container to operate with manifest objects
        :param key: 'kind' and 'name' of object
        :param container_name: name of container to assign the image in the spec
        :param is_init_container: whether to search container in 'initContainers' or in 'containers' spec.
        :param allow_absent: if True, and if container is not found, return -1, None
        :return: tuple of container index within the spec and the container data.
        """
        source_yaml = manifest.get_obj(key, patch=True)
        template_spec = source_yaml['spec']['template']['spec']
        spec_containers_section = 'initContainers' if is_init_container else 'containers'
        container_pos, container = next(((i, c) for i, c in enumerate(template_spec[spec_containers_section])
                                         if c['name'] == container_name),
                                        (-1, None))

        if container_pos == -1 and not allow_absent:
            raise ValueError(f"Container {container_name!r} is not found in {spec_containers_section!r} spec of {key}")

        return container_pos, container

    def get_target_image(self, plugin_service: Optional[str] = None, image_key: Optional[str] = 'image'):
        """
        Calculates full image path from the plugin configuration in inventory.

        :param plugin_service: section of plugin that contains the desirable image_key
        :param image_key: property name by which the inventory holds the desirable image
        :return: target image to be used in a container
        """
        plugin_section = self.inventory['plugins'][self.plugin_name]
        registry = plugin_section['installation'].get('registry')
        plugin_service_section = plugin_section
        if plugin_service:
            plugin_service_section = plugin_service_section[plugin_service]
        image = plugin_service_section[image_key]
        if registry:
            image = f"{registry}/{image}"

        return image

    def enrich_image_for_container(self, manifest: Manifest, key: str,
                                   *,
                                   plugin_service: Optional[str] = None,
                                   container_name: str, is_init_container: bool,
                                   allow_absent=False) -> None:
        """
        The method patches the image of the specified container.

        :param manifest: container to operate with manifest objects
        :param key: 'kind' and 'name' of object
        :param plugin_service: section of plugin that contains the desirable 'image'
        :param container_name: name of container to assign the image in the spec
        :param is_init_container: whether to search container in 'initContainers' or in 'containers' spec.
        :param allow_absent: if True, and if container is not found, silently do nothing.
        """
        image = self.get_target_image(plugin_service=plugin_service, image_key='image')

        spec_containers_section = 'initContainers' if is_init_container else 'containers'

        container_pos, container = self.find_container_for_patch(manifest, key,
            container_name=container_name, is_init_container=is_init_container, allow_absent=allow_absent)
        if container_pos == -1:
            return

        container['image'] = image
        self.log.verbose(f"The {key} has been patched in "
                         f"'spec.template.spec.{spec_containers_section}.[{container_pos}].image' with {image!r}")

    def enrich_node_selector(self, manifest: Manifest, key: str,
                             *,
                             plugin_service: str):
        source_yaml = manifest.get_obj(key, patch=True)
        node_selector = self.inventory['plugins'][self.plugin_name][plugin_service]['nodeSelector']
        source_yaml['spec']['template']['spec']['nodeSelector'] = node_selector
        self.log.verbose(f"The {key} has been patched in 'spec.template.spec.nodeSelector' with {node_selector!r}")

    def enrich_tolerations(self, manifest: Manifest, key: str,
                           *,
                           plugin_service: Optional[str] = None,
                           extra_tolerations: List[dict] = None,
                           override=False):
        source_yaml = manifest.get_obj(key, patch=True)
        template_spec: dict = source_yaml['spec']['template']['spec']
        if override and template_spec.get('tolerations', []):
            del template_spec['tolerations']
            self.log.verbose(f"The 'tolerations' property has been removed from 'spec.template.spec' in the {key}")

        tolerations: List[dict] = []
        if extra_tolerations:
            tolerations.extend(extra_tolerations)
        plugin_service_section = self.inventory['plugins'][self.plugin_name]
        if plugin_service:
            plugin_service_section = plugin_service_section[plugin_service]
        tolerations.extend(plugin_service_section.get('tolerations', []))

        for val in tolerations:
            template_spec.setdefault('tolerations', []).append(val)
            self.log.verbose(f"The {key} has been patched in 'spec.template.spec.tolerations' with '{val}'")


PROCESSOR_PROVIDER = Callable[[KubernetesCluster, dict, str, str], Processor]
