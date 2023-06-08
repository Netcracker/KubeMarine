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

from typing import Dict

from kubemarine.core import log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins import manifest
from kubemarine.plugins.calico import CalicoManifestProcessor
from kubemarine.plugins.kubernetes_dashboard import get_dashboard_manifest_processor
from kubemarine.plugins.local_path_provisioner import LocalPathProvisionerManifestProcessor
from kubemarine.plugins.nginx_ingress import get_ingress_nginx_manifest_processor

MANIFEST_PROCESSOR_PROVIDERS: Dict[str, manifest.PROCESSOR_PROVIDER] = {
    "calico": CalicoManifestProcessor,
    "nginx-ingress-controller": get_ingress_nginx_manifest_processor,
    "kubernetes-dashboard": get_dashboard_manifest_processor,
    "local-path-provisioner": LocalPathProvisionerManifestProcessor,
}


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    for plugin_name, processor_provider in MANIFEST_PROCESSOR_PROVIDERS.items():
        if not inventory["plugins"][plugin_name]["install"]:
            continue

        items = inventory['plugins'][plugin_name]['installation']['procedures']
        for i, item in enumerate(items):
            if 'python' not in item:
                continue

            config: dict = item['python']
            if config['module'] != "plugins/builtin.py" or config['method'] != "apply_yaml":
                continue

            arguments = dict(config.get('arguments', {}))
            declared_name = arguments.pop('plugin_name', None)
            if declared_name != plugin_name:
                raise Exception(f"Unexpected 'plugin_name={declared_name}' argument "
                                f"in {plugin_name!r} installation step {i}.")

            expected_args = {'plugin_name', 'original_yaml_path', 'destination_name'}
            declared_args = set(arguments.keys())
            if not declared_args.issubset(expected_args):
                raise Exception(f"Unexpected python method arguments {list(declared_args.difference(expected_args))} "
                                f"in {plugin_name!r} installation step {i}.")

            processor = processor_provider(
                cluster.log, inventory, arguments.get('original_yaml_path'), arguments.get('destination_name')
            )
            processor.validate_inventory()
            break
        else:
            cluster.log.warning(f"Invocation of plugins.builtin.apply_yaml is not found for {plugin_name!r} plugin. "
                                f"Such configuration is obsolete, and support for it may be stopped in future releases.")

    return inventory


def get_manifest_processor(logger: log.VerboseLogger, inventory: dict, plugin_name: str,
                           **arguments: str) -> manifest.Processor:
    if plugin_name not in MANIFEST_PROCESSOR_PROVIDERS:
        raise Exception(f"Manifest processor is not registered for {plugin_name!r} plugin.")

    processor_provider = MANIFEST_PROCESSOR_PROVIDERS[plugin_name]
    return processor_provider(logger, inventory, arguments.get('original_yaml_path'), arguments.get('destination_name'))


def apply_yaml(cluster: KubernetesCluster, **arguments: str) -> None:
    arguments = dict(arguments)
    plugin_name = arguments.pop('plugin_name')

    processor = get_manifest_processor(cluster.log, cluster.inventory, plugin_name, **arguments)

    manifest = processor.enrich()
    processor.apply(cluster, manifest)
