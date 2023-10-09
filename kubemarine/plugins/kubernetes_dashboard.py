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
from typing import List, Optional, Dict

from kubemarine.core import summary, utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if not inventory["plugins"]["kubernetes-dashboard"]["install"]:
        return inventory

    # if user defined resources himself, we should use them as is, instead of merging with our defaults
    raw_dashboard = cluster.raw_inventory.get("plugins", {}).get("kubernetes-dashboard", {}).get("dashboard", {})
    if "resources" in raw_dashboard:
        inventory["plugins"]["kubernetes-dashboard"]["dashboard"]["resources"] = raw_dashboard["resources"]
    raw_metrics_scrapper = cluster.raw_inventory.get("plugins", {}).get("kubernetes-dashboard", {}).get("metrics-scraper", {})
    if "resources" in raw_metrics_scrapper:
        inventory["plugins"]["kubernetes-dashboard"]["metrics-scraper"]["resources"] = raw_metrics_scrapper["resources"]

    return inventory


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
            self.enrich_deployment_kubernetes_dashboard,
            self.enrich_deployment_dashboard_metrics_scraper,
        ]

    def get_namespace_to_necessary_pss_profiles(self) -> Dict[str, str]:
        return {'kubernetes-dashboard': 'baseline'}

    def enrich_namespace_kubernetes_dashboard(self, manifest: Manifest) -> None:
        self.assign_default_pss_labels(manifest, 'kubernetes-dashboard')

    def enrich_deployment_kubernetes_dashboard(self, manifest: Manifest) -> None:
        key = "Deployment_kubernetes-dashboard"
        self.enrich_image_for_container(manifest, key,
            plugin_service='dashboard', container_name='kubernetes-dashboard', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='kubernetes-dashboard', plugin_service="dashboard")
        self.enrich_node_selector(manifest, key, plugin_service='dashboard')
        self.enrich_tolerations(manifest, key, plugin_service='dashboard', override=True)

    def enrich_deployment_dashboard_metrics_scraper(self, manifest: Manifest) -> None:
        key = "Deployment_dashboard-metrics-scraper"
        self.enrich_image_for_container(manifest, key,
            plugin_service='metrics-scraper', container_name='dashboard-metrics-scraper', is_init_container=False)

        self.enrich_resources_for_container(manifest, key, container_name='dashboard-metrics-scraper', plugin_service="metrics-scraper")
        self.enrich_node_selector(manifest, key, plugin_service='metrics-scraper')
        self.enrich_tolerations(manifest, key, plugin_service='metrics-scraper', override=True)


class V2_5_X_DashboardManifestProcessor(DashboardManifestProcessor):
    def enrich_deployment_dashboard_metrics_scraper(self, manifest: Manifest) -> None:
        key = "Deployment_dashboard-metrics-scraper"
        source_yaml = manifest.get_obj(key, patch=True)
        template_spec: dict = source_yaml['spec']['template']['spec']
        del template_spec['securityContext']
        self.log.verbose(f"The 'securityContext' property has been removed from 'spec.template.spec' in the {key}")
        super().enrich_deployment_dashboard_metrics_scraper(manifest)


def get_dashboard_manifest_processor(logger: log.VerboseLogger, inventory: dict,
                                     yaml_path: Optional[str] = None, destination: Optional[str] = None) -> Processor:
    version: str = inventory['plugins']['kubernetes-dashboard']['version']
    kwargs = {'original_yaml_path': yaml_path, 'destination_name': destination}
    if utils.minor_version(version) == 'v2.5':
        return V2_5_X_DashboardManifestProcessor(logger, inventory, **kwargs)

    return DashboardManifestProcessor(logger, inventory, **kwargs)
