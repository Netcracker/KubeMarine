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

from textwrap import dedent
from typing import List, Optional, Dict

import yaml

from kubemarine.core import log
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    if not inventory["plugins"]["local-path-provisioner"]["install"]:
        return

    # if user defined resources himself, we should use them as is, instead of merging with our defaults
    raw_plugin = cluster.raw_inventory.get("plugins", {}).get("local-path-provisioner", {})
    if "resources" in raw_plugin:
        inventory["plugins"]["local-path-provisioner"]["resources"] = raw_plugin["resources"]


class LocalPathProvisionerManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None) -> None:
        super().__init__(logger, inventory, Identity('local-path-provisioner'), original_yaml_path, destination_name)

    def get_known_objects(self) -> List[str]:
        return [
            "Namespace_local-path-storage",
            "ServiceAccount_local-path-provisioner-service-account",
            "Role_local-path-provisioner-role",
            "ClusterRole_local-path-provisioner-role",
            "RoleBinding_local-path-provisioner-bind",
            "ClusterRoleBinding_local-path-provisioner-bind",
            "Deployment_local-path-provisioner",
            "StorageClass_local-path",
            "ConfigMap_local-path-config",
        ]

    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        return [
            self.enrich_namespace_local_path_storage,
            self.enrich_service_account,
            self.enrich_service_account_secret,
            self.enrich_deployment_local_path_provisioner,
            self.enrich_storageclass_local_path,
            self.enrich_configmap_local_path_config,
        ]

    def get_namespace_to_necessary_pss_profiles(self) -> Dict[str, str]:
        return {'local-path-storage': 'privileged'}

    def enrich_namespace_local_path_storage(self, manifest: Manifest) -> None:
        self.assign_default_pss_labels(manifest, 'local-path-storage')

    def enrich_service_account_secret(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret)

        service_account_key = "ServiceAccount_local-path-provisioner-service-account"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1
        
        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account(self, manifest: Manifest) -> None:
        key = "ServiceAccount_local-path-provisioner-service-account"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False

    def enrich_deployment_local_path_provisioner(self, manifest: Manifest) -> None:
        service_account_name = "local-path-provisioner-service-account"
        key = "Deployment_local-path-provisioner"

        source_yaml = manifest.get_obj(key, patch=True)
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
        self.log.verbose(f"The {key} has been updated to include the new secret volume and mount.")

        self.enrich_image_for_container(manifest, key,
            container_name='local-path-provisioner', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='local-path-provisioner')
        self.enrich_tolerations(manifest, key)

    def enrich_storageclass_local_path(self, manifest: Manifest) -> None:
        key = "StorageClass_local-path"
        source_yaml = manifest.get_obj(key, patch=True)
        metadata = source_yaml['metadata']

        is_default = str(self.inventory['plugins']['local-path-provisioner']['storage-class']['is-default'])
        metadata.setdefault('annotations', {})['storageclass.kubernetes.io/is-default-class'] = is_default
        self.log.verbose(f"The {key} has been patched in 'metadata.annotations' "
                         f"with 'storageclass.kubernetes.io/is-default-class: {is_default}'")

        name = self.inventory['plugins']['local-path-provisioner']['storage-class']['name']
        metadata['name'] = self.inventory['plugins']['local-path-provisioner']['storage-class']['name']
        self.log.verbose(f"The {key} has been patched in 'metadata.name' with {name!r}")

    def enrich_configmap_local_path_config(self, manifest: Manifest) -> None:
        key = "ConfigMap_local-path-config"
        source_yaml = manifest.get_obj(key, patch=True)
        data = source_yaml['data']

        config_json = data['config.json']
        config_json = config_json.replace('/opt/local-path-provisioner',
                                          self.inventory['plugins']['local-path-provisioner']['volume-dir'])
        data['config.json'] = config_json
        config_json_oneline = config_json.replace('\n', ' ')
        self.log.verbose(f"The {key} has been patched in 'data.config.json' with {config_json_oneline!r}")

        helperpod_yaml_str = data['helperPod.yaml']
        helperpod_yaml = yaml.safe_load(helperpod_yaml_str)
        busybox_source_image = helperpod_yaml['spec']['containers'][0]['image']
        helperpod_yaml_str = helperpod_yaml_str.replace(
            busybox_source_image, self.get_target_image(image_key='helper-pod-image'))
        data['helperPod.yaml'] = helperpod_yaml_str
        helperpod_yaml_str_oneline = helperpod_yaml_str.replace('\n', ' ')
        self.log.verbose(f"The {key} has been patched in 'data.helperPod.yaml' with {helperpod_yaml_str_oneline!r}")


service_account_secret = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: local-path-provisioner-service-account-token
      namespace: local-path-storage
      annotations:
        kubernetes.io/service-account.name: local-path-provisioner-service-account
    type: kubernetes.io/service-account-token  
""")
