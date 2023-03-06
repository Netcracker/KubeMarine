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

from typing import Optional, Dict, Type

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins import manifest
from kubemarine.plugins.calico import CalicoManifestProcessor

MANIFEST_PROCESSORS: Dict[str, Type[manifest.Processor]] = {
    "calico": CalicoManifestProcessor,
}


def verify_inventory(inventory: dict, cluster: KubernetesCluster):
    for plugin_name, processor_cls in MANIFEST_PROCESSORS.items():
        if not inventory["plugins"][plugin_name]["install"]:
            continue

        items = inventory['plugins'][plugin_name]['installation']['procedures']
        for i, item in enumerate(items):
            if 'python' not in item:
                continue

            config: dict = item['python']
            if config['module'] != "plugins/builtin.py" or config['method'] != "apply_yaml":
                continue

            arguments = config.get('arguments', {})
            declared_name = arguments.get('plugin_name')
            if declared_name != plugin_name:
                raise Exception(f"Unexpected 'plugin_name={declared_name}' argument "
                                f"in {plugin_name!r} installation step {i}.")

            expected_args = {'plugin_name', 'original_yaml_path', 'destination_name'}
            declared_args = set(arguments.keys())
            if not declared_args.issubset(expected_args):
                raise Exception(f"Unexpected python method arguments {list(declared_args.difference(expected_args))} "
                                f"in {plugin_name!r} installation step {i}.")

            processor_cls(cluster, inventory, **arguments).validate_inventory()
            break
        else:
            cluster.log.warning(f"Invocation of plugins.builtin.apply_yaml is not found for {plugin_name!r} plugin. "
                                f"Such configuration is obsolete, and support for it may be stopped in future releases.")

    return inventory


def apply_yaml(cluster: KubernetesCluster, plugin_name: str,
               original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
    if plugin_name not in MANIFEST_PROCESSORS:
        raise Exception(f"Manifest processor is not registered for {plugin_name!r} plugin.")

    processor_cls = MANIFEST_PROCESSORS[plugin_name]
    processor = processor_cls(cluster, cluster.inventory,
                              plugin_name=plugin_name,
                              original_yaml_path=original_yaml_path, destination_name=destination_name)
    processor.apply()
