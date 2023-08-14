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
from typing import Callable, Optional, List, IO, Tuple, cast

import ruamel.yaml
import os
from abc import ABC, abstractmethod

from ordered_set import OrderedSet

from kubemarine import plugins
from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster

ERROR_MANIFEST_NOT_FOUND = "Cannot find original manifest %s for '%s' plugin"


def get_default_manifest_path(plugin_name: str, version: str) -> str:
    resource = f"plugins/yaml/{plugin_name}-{version}-original.yaml"
    return utils.get_internal_resource_path(resource)


class Manifest:
    def __init__(self, stream: IO) -> None:
        self._patched = OrderedSet[str]()
        self._excluded = OrderedSet[str]()
        self._included = OrderedSet[str]()
        self._obj_list = self._load(stream)

    def obj_key(self, obj: dict) -> str:
        return f"{obj['kind']}_{obj['metadata']['name']}"

    def all_obj_keys(self) -> List[str]:
        return [self.obj_key(obj) for obj in self._obj_list]

    def key_index(self, key: str) -> int:
        for i, obj in enumerate(self._obj_list):
            if self.obj_key(obj) == key:
                return i

        raise ValueError(f"{key} not found")

    def has_obj(self, key: str) -> bool:
        return any(self.obj_key(obj) == key for obj in self._obj_list)

    def get_obj(self, key: str, *, patch: bool) -> dict:
        """
        Get manifest object in YAML format for the specified key.
        By default, ensure presence of the object.
        If the object is absent, it may be a sign that we no longer able to fulfill the previous contract.
        Caller methods must explicitly allow absent object when necessary.

        :param key: 'kind' and 'name' of object
        :param patch: boolean value that tells the manifest that the searched object is going to be patched.
        :return: manifest object
        """
        for obj in self._obj_list:
            if self.obj_key(obj) == key:
                if patch:
                    self._patched.add(key)
                return obj

        raise ValueError(f"{key} not found")

    def include(self, index: int, obj: dict) -> None:
        self._obj_list.insert(index, obj)
        key = self.obj_key(obj)
        self._included.add(key)

    def exclude(self, key: str) -> None:
        del self._obj_list[self.key_index(key)]
        self._excluded.add(key)

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

    def get_all_container_images(self) -> List[str]:
        images = []
        for key in self.all_obj_keys():
            obj = self.get_obj(key, patch=False)
            for spec_section in ('containers', 'initContainers'):
                containers = obj.get('spec', {}).get('template', {}).get('spec', {}).get(spec_section, [])
                for container in containers:
                    image = container['image']
                    if image not in images:
                        images.append(image)

        return images

    def _load(self, stream: IO) -> List[dict]:
        """
        The method implements the parse YAML file that includes several YAMLs inside
        :param stream: stream with manifest content that should be parsed
        :return: list of original objects to enrich in YAML format.
        """
        yaml = ruamel.yaml.YAML()
        obj_list = []
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
    def __init__(self, logger: log.VerboseLogger, inventory: dict, plugin_name: str,
                 original_yaml_path: Optional[str], destination_name: Optional[str]) -> None:
        """
        :param logger: VerboseLogger instance
        :param inventory: inventory of the cluster
        :param plugin_name: name of plugin-owner
        :param original_yaml_path: path to custom manifest
        :param destination_name: custom destination manifest file name
        """
        self.log: log.VerboseLogger = logger
        self.inventory = inventory
        self.plugin_name = plugin_name
        self.manifest_path = self._get_manifest_path(original_yaml_path)
        self.destination_name = self._get_destination(destination_name)

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

    def get_version(self) -> str:
        version: str = self.inventory['plugins'][self.plugin_name]['version']
        return version

    def include(self, manifest: Manifest, index: int, obj: dict) -> None:
        key = manifest.obj_key(obj)
        manifest.include(index, obj)
        self.log.verbose(f"The {key} has been added")

    def exclude(self, manifest: Manifest, key: str) -> None:
        manifest.exclude(key)
        self.log.verbose(f"The {key} has been excluded from result")

    def validate_inventory(self) -> None:
        """
        # Check if original YAML exists
        """
        if not os.path.isfile(self.manifest_path):
            raise Exception(ERROR_MANIFEST_NOT_FOUND % (self.manifest_path, self.plugin_name))

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
            if not manifest.has_obj(key):
                self.log.verbose(f"The current version of original yaml does not include "
                                 f"the following object: {key}")

    def enrich(self) -> Manifest:
        """
        The method implements full processing for the plugin main manifest.
        """

        # get original YAML and parse it into list of objects
        try:
            with utils.open_utf8(self.manifest_path, 'r') as stream:
                manifest = Manifest(stream)
        except Exception as exc:
            raise Exception(f"Failed to load {self.manifest_path} for {self.plugin_name!r} plugin") from exc

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

        return manifest

    def apply(self, cluster: KubernetesCluster, manifest: Manifest) -> None:
        logger = cluster.log
        enriched_manifest = manifest.dump()
        utils.dump_file(cluster, enriched_manifest, self.destination_name)

        destination = '/etc/kubernetes/%s' % self.destination_name

        # create config for plugin module
        config = {
            "source": io.StringIO(enriched_manifest),
            "destination": destination,
            "do_render": False
        }

        logger.debug(f"Uploading manifest enriched from {self.manifest_path} for {self.plugin_name!r} plugin...")
        logger.debug("\tDestination: %s" % destination)

        plugins.apply_source(cluster, config)

    def _get_manifest_path(self, custom_manifest_path: Optional[str]) -> str:
        if custom_manifest_path is not None:
            config = {"source": custom_manifest_path}
            manifest_path, _ = plugins.get_source_absolute_pattern(config)
        else:
            manifest_path = get_default_manifest_path(self.plugin_name, self.get_version())

        return manifest_path

    def _get_destination(self, custom_destination_name: Optional[str]) -> str:
        if custom_destination_name is not None:
            return custom_destination_name

        return f'{self.plugin_name}-{self.get_version()}.yaml'

    def assign_default_pss_labels(self, manifest: Manifest, key: str, profile: str) -> None:
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
                                 container_name: str, is_init_container: bool) -> Tuple[int, dict]:
        """
        Find container according to the search criteria.

        :param manifest: container to operate with manifest objects
        :param key: 'kind' and 'name' of object
        :param container_name: name of container to assign the image in the spec
        :param is_init_container: whether to search container in 'initContainers' or in 'containers' spec.
        :return: tuple of container index within the spec and the container data.
        """
        pos, container = self._find_optional_container(
            manifest, key,
            container_name=container_name, is_init_container=is_init_container, allow_absent=False)

        return pos, cast(dict, container)

    def _find_optional_container(self, manifest: Manifest, key: str,
                                 container_name: str, is_init_container: bool, allow_absent: bool = False) \
            -> Tuple[int, Optional[dict]]:
        source_yaml = manifest.get_obj(key, patch=True)
        template_spec = source_yaml['spec']['template']['spec']
        spec_containers_section = 'initContainers' if is_init_container else 'containers'
        container_pos, container = next(((i, c) for i, c in enumerate(template_spec[spec_containers_section])
                                         if c['name'] == container_name),
                                        (-1, None))

        if container_pos == -1 and not allow_absent:
            raise ValueError(f"Container {container_name!r} is not found in {spec_containers_section!r} spec of {key}")

        return container_pos, container

    def get_target_image(self, plugin_service: Optional[str] = None, image_key: Optional[str] = 'image') -> str:
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
        image: str = plugin_service_section[image_key]
        if registry:
            image = f"{registry}/{image}"

        return image

    def enrich_image_for_container(self, manifest: Manifest, key: str,
                                   *,
                                   plugin_service: Optional[str] = None,
                                   container_name: str, is_init_container: bool,
                                   allow_absent: bool = False) -> None:
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

        container_pos, container = self._find_optional_container(manifest, key,
            container_name=container_name, is_init_container=is_init_container, allow_absent=allow_absent)
        if container is None:
            return

        container['image'] = image
        self.log.verbose(f"The {key} has been patched in "
                         f"'spec.template.spec.{spec_containers_section}.[{container_pos}].image' with {image!r}")

    def enrich_resources_for_container(self, manifest: Manifest, key: str,
                                       *,
                                       plugin_service: Optional[str] = None,
                                       container_name: str) -> None:
        """
        The method patches the resources of the specified container.

        :param manifest: container to operate with manifest objects
        :param key: 'kind' and 'name' of object
        :param plugin_service: section of plugin that contains the desirable 'resources'
        :param container_name: name of container to assign the resources in the spec
        """
        container_pos, container = self.find_container_for_patch(manifest, key,
                                                                 container_name=container_name, is_init_container=False)

        plugin_service_section = self.inventory['plugins'][self.plugin_name]
        if plugin_service:
            plugin_service_section = plugin_service_section[plugin_service]
        container['resources'] = plugin_service_section['resources']

        self.log.verbose(f"The {key} has been patched in "
                         f"'spec.template.spec.containers.[{container_pos}].resources' with {plugin_service_section['resources']!r}")

    def enrich_node_selector(self, manifest: Manifest, key: str,
                             *,
                             plugin_service: str) -> None:
        source_yaml = manifest.get_obj(key, patch=True)
        node_selector = self.inventory['plugins'][self.plugin_name][plugin_service]['nodeSelector']
        source_yaml['spec']['template']['spec']['nodeSelector'] = node_selector
        self.log.verbose(f"The {key} has been patched in 'spec.template.spec.nodeSelector' with {node_selector!r}")

    def enrich_tolerations(self, manifest: Manifest, key: str,
                           *,
                           plugin_service: Optional[str] = None,
                           extra_tolerations: List[dict] = None,
                           override: bool = False) -> None:
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


PROCESSOR_PROVIDER = Callable[[log.VerboseLogger, dict, Optional[str], Optional[str]], Processor]
