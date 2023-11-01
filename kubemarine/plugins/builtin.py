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

from typing import Dict, Optional

from kubemarine.core import log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins import calico, manifest
from kubemarine.plugins.calico import CalicoManifestProcessor, CalicoApiServerManifestProcessor
from kubemarine.plugins.kubernetes_dashboard import get_dashboard_manifest_processor
from kubemarine.plugins.local_path_provisioner import LocalPathProvisionerManifestProcessor
from kubemarine.plugins.manifest import Identity
from kubemarine.plugins.nginx_ingress import get_ingress_nginx_manifest_processor

MANIFEST_PROCESSOR_PROVIDERS: Dict[Identity, manifest.PROCESSOR_PROVIDER] = {
    Identity("calico"): CalicoManifestProcessor,
    Identity("calico", "apiserver"): CalicoApiServerManifestProcessor,
    Identity("nginx-ingress-controller"): get_ingress_nginx_manifest_processor,
    Identity("kubernetes-dashboard"): get_dashboard_manifest_processor,
    Identity("local-path-provisioner"): LocalPathProvisionerManifestProcessor,
}


def is_manifest_installed(cluster: KubernetesCluster, manifest_identity: Identity) -> bool:
    """
    Checks if the manifest is (to be) installed during the regular installation procedure.

    :param cluster: KubernetesCluster object
    :param manifest_identity: A pair of (plugin_name, manifest_id) that uniquely identifies the manifest
    :return: `true` is manifest is (to be) installed.
    """
    return get_manifest_processor(cluster, manifest_identity) is not None


def get_manifest_processor(cluster: KubernetesCluster, manifest_identity: Identity) -> Optional[manifest.Processor]:
    """
    Return actual manifest processor if it is (to be) installed during the regular installation procedure.

    :param cluster: KubernetesCluster object
    :param manifest_identity: A pair of (plugin_name, manifest_id) that uniquely identifies the manifest
    :return: actual manifest processor
    """
    if _is_manifest_disabled(cluster.inventory, manifest_identity):
        return None

    config = _get_manifest_installation_step(cluster.inventory, manifest_identity)
    if config is None:
        return None

    return _convert_config_to_manifest_processor(cluster.log, cluster.inventory, config)


def _convert_config_to_manifest_processor(logger: log.VerboseLogger, inventory: dict, config: dict) -> manifest.Processor:
    arguments = config['arguments']
    manifest_identity = Identity(arguments['plugin_name'], arguments.get('manifest_id'))

    return _get_manifest_processor(
        logger, inventory, manifest_identity,
        arguments.get('original_yaml_path'), arguments.get('destination_name'))


def _get_manifest_installation_step(inventory: dict, manifest_identity: Identity) -> Optional[dict]:
    plugin_name = manifest_identity.plugin_name
    items = inventory['plugins'][plugin_name]['installation']['procedures']
    for i, item in enumerate(items):
        if 'python' not in item:
            continue

        config: dict = item['python']
        if config['module'] != "plugins/builtin.py" or config['method'] != "apply_yaml":
            continue

        # presence of arguments and signature of apply_yaml is validated in plugins.verify_python
        arguments = config['arguments']
        declared_name = arguments['plugin_name']
        if declared_name != plugin_name:
            raise Exception(f"Unexpected 'plugin_name={declared_name}' argument "
                            f"in {plugin_name!r} installation step {i}.")

        declared_identity = Identity(plugin_name, arguments.get('manifest_id'))
        if manifest_identity != declared_identity:
            continue

        return config

    return None


def _is_manifest_disabled(inventory: dict, manifest_identity: Identity) -> bool:
    plugin_name = manifest_identity.plugin_name
    if not inventory["plugins"][plugin_name]["install"]:
        return True

    if manifest_identity == Identity("calico", "apiserver") and not calico.is_apiserver_enabled(inventory):
        return True

    return False


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    for manifest_identity in MANIFEST_PROCESSOR_PROVIDERS:
        if _is_manifest_disabled(inventory, manifest_identity):
            continue

        config = _get_manifest_installation_step(inventory, manifest_identity)
        if config is not None:
            processor = _convert_config_to_manifest_processor(cluster.log, inventory, config)
            processor.validate_inventory()
        else:
            cluster.log.warning(f"Invocation of plugins.builtin.apply_yaml for {manifest_identity.repr_id()} "
                                f"is not found for {manifest_identity.plugin_name!r} plugin. "
                                f"Such configuration is obsolete, and support for it may be stopped in future releases.")

    return inventory


def _get_manifest_processor(logger: log.VerboseLogger, inventory: dict, manifest_identity: Identity,
                            original_yaml_path: Optional[str] = None,
                            destination_name: Optional[str] = None) -> manifest.Processor:
    if manifest_identity not in MANIFEST_PROCESSOR_PROVIDERS:
        raise Exception(f"Cannot find processor of {manifest_identity.repr_id()} "
                        f"for {manifest_identity.plugin_name!r} plugin.")

    processor_provider = MANIFEST_PROCESSOR_PROVIDERS[manifest_identity]
    return processor_provider(logger, inventory, original_yaml_path, destination_name)


def apply_yaml(cluster: KubernetesCluster, plugin_name: str,
               manifest_id: Optional[str] = None,
               original_yaml_path: Optional[str] = None,
               destination_name: Optional[str] = None) -> None:
    manifest_identity = Identity(plugin_name, manifest_id)
    # Since the method is called from the inventory, the installation step is certainly present.
    # Though it can still be disabled by other inventory properties.
    if _is_manifest_disabled(cluster.inventory, manifest_identity):
        cluster.log.debug(f"Skip installing of the {manifest_identity.repr_id()} for {plugin_name!r} plugin.")
        return

    processor = _get_manifest_processor(cluster.log, cluster.inventory, manifest_identity,
                                        original_yaml_path, destination_name)

    manifest = processor.enrich()
    processor.apply(cluster, manifest)


def get_namespace_to_necessary_pss_profiles(cluster: KubernetesCluster) -> Dict[str, str]:
    """
    :param cluster: KubernetesCluster object
    :return: minimal required PSS profiles for all installed plugins' namespaces
    """
    result = {}
    for manifest_identity in MANIFEST_PROCESSOR_PROVIDERS:
        # Use _is_manifest_disabled() instead of `not is_manifest_installed()`,
        # because old inventories might still refer to .yaml.j2 templates where PSS was also managed automatically.
        if _is_manifest_disabled(cluster.inventory, manifest_identity):
            continue

        processor = _get_manifest_processor(cluster.log, cluster.inventory, manifest_identity)
        result.update(processor.get_namespace_to_necessary_pss_profiles())

    return result
