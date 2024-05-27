# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from textwrap import dedent
from typing import List, Optional, Dict
import yaml

from kubemarine.core import summary, log
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    if not inventory["plugins"]["kubernetes-dashboard"]["install"]:
        return

    # if user defined resources himself, we should use them as is, instead of merging with our defaults
    raw_dashboard = cluster.raw_inventory.get("plugins", {}).get("kubernetes-dashboard", {}).get("dashboard", {})
    if "resources" in raw_dashboard:
        inventory["plugins"]["kubernetes-dashboard"]["dashboard"]["resources"] = raw_dashboard["resources"]
    raw_metrics_scrapper = cluster.raw_inventory.get("plugins", {}).get("kubernetes-dashboard", {}).get("metrics-scraper", {})
    if "resources" in raw_metrics_scrapper:
        inventory["plugins"]["kubernetes-dashboard"]["metrics-scraper"]["resources"] = raw_metrics_scrapper["resources"]


def schedule_summary_report(cluster: KubernetesCluster) -> None:
    plugin_item = cluster.inventory['plugins']['kubernetes-dashboard']
    hostname = plugin_item['hostname']
    # Currently we declare that Dashboard UI is available only via HTTPS
    summary.schedule_report(cluster.context, summary.SummaryItem.DASHBOARD_URL, f'https://{hostname}')


class DashboardManifestProcessor(Processor):
    def __init__(self, logger: log.VerboseLogger, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None) -> None:
        super().__init__(logger, inventory, Identity('kubernetes-dashboard'), original_yaml_path, destination_name)

    def get_known_objects(self) -> List[str]:
        return [
            "Namespace_kubernetes-dashboard",
            "ServiceAccount_kubernetes-dashboard",
            "Service_kubernetes-dashboard",
            "Secret_kubernetes-dashboard-certs",
            "Secret_kubernetes-dashboard-csrf",
            "Secret_kubernetes-dashboard-key-holder",
            "ConfigMap_kubernetes-dashboard-settings",
            "Role_kubernetes-dashboard",
            "ClusterRole_kubernetes-dashboard",
            "RoleBinding_kubernetes-dashboard",
            "ClusterRoleBinding_kubernetes-dashboard",
            "Deployment_kubernetes-dashboard",
            "Service_dashboard-metrics-scraper",
            "Deployment_dashboard-metrics-scraper",
        ]

    def get_enrichment_functions(self) -> List[EnrichmentFunction]:
        return [
            self.enrich_namespace_kubernetes_dashboard,
            self.enrich_service_account_secret_kubernetes_dashboard,
            self.enrich_service_account_kubernetes_dashboard,
            self.enrich_deployment_kubernetes_dashboard,
            self.enrich_deployment_dashboard_metrics_scraper,
        ]

    def get_namespace_to_necessary_pss_profiles(self) -> Dict[str, str]:
        return {'kubernetes-dashboard': 'baseline'}

    def enrich_namespace_kubernetes_dashboard(self, manifest: Manifest) -> None:
        self.assign_default_pss_labels(manifest, 'kubernetes-dashboard')

    def enrich_service_account_secret_kubernetes_dashboard(self, manifest: Manifest) -> None:
        new_yaml = yaml.safe_load(service_account_secret_kubernetes_dashboard)

        service_account_key = "ServiceAccount_kubernetes-dashboard"
        service_account_index = manifest.all_obj_keys().index(service_account_key) \
            if service_account_key in manifest.all_obj_keys() else -1
        
        self.include(manifest, service_account_index + 1, new_yaml)

    def enrich_service_account_kubernetes_dashboard(self, manifest: Manifest) -> None:
        key = "ServiceAccount_kubernetes-dashboard"
        source_yaml = manifest.get_obj(key, patch=True)
        source_yaml['automountServiceAccountToken'] = False

    def enrich_deployment_kubernetes_dashboard(self, manifest: Manifest) -> None:
        key = "Deployment_kubernetes-dashboard"
        source_yaml = manifest.get_obj(key, patch=True)
        
        service_account_name = "kubernetes-dashboard"
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
       
        self.log.verbose(f"The {key} has been updated to include the new secret volume and mount.")

        self.enrich_image_for_container(manifest, key,
            plugin_service='dashboard', container_name='kubernetes-dashboard', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='kubernetes-dashboard', plugin_service="dashboard")
        self.enrich_node_selector(manifest, key, plugin_service='dashboard')
        self.enrich_tolerations(manifest, key, plugin_service='dashboard', override=True)

    def enrich_deployment_dashboard_metrics_scraper(self, manifest: Manifest) -> None:
        key = "Deployment_dashboard-metrics-scraper"
        source_yaml = manifest.get_obj(key, patch=True)
        
        service_account_name = "kubernetes-dashboard"
        self.enrich_volume_and_volumemount(source_yaml, service_account_name)
       
        self.log.verbose(f"The {key} has been updated to include the new secret volume and mount.")

        self.enrich_image_for_container(manifest, key,
            plugin_service='metrics-scraper', container_name='dashboard-metrics-scraper', is_init_container=False)

        self.enrich_resources_for_container(
            manifest, key, container_name='dashboard-metrics-scraper', plugin_service="metrics-scraper")
        self.enrich_node_selector(manifest, key, plugin_service='metrics-scraper')
        self.enrich_tolerations(manifest, key, plugin_service='metrics-scraper', override=True)


service_account_secret_kubernetes_dashboard = dedent("""\
    apiVersion: v1
    kind: Secret
    metadata:
      name: kubernetes-dashboard-token
      namespace: kubernetes-dashboard
      annotations:
        kubernetes.io/service-account.name: kubernetes-dashboard
    type: kubernetes.io/service-account-token  
""")
