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
from typing import List, Optional

from kubemarine.core import summary
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest


def schedule_summary_report(cluster: KubernetesCluster):
    plugin_item = cluster.inventory['plugins']['kubernetes-dashboard']
    hostname = plugin_item['hostname']
    # Currently we declare that Dashboard UI is available only via HTTPS
    summary.schedule_report(cluster.context, summary.SummaryItem.DASHBOARD_URL, f'https://{hostname}')


class DashboardManifestProcessor(Processor):
    def __init__(self, cluster: KubernetesCluster, inventory: dict,
                 original_yaml_path: Optional[str] = None, destination_name: Optional[str] = None):
        plugin_name = 'kubernetes-dashboard'
        version = inventory['plugins'][plugin_name]['version']
        if original_yaml_path is None:
            original_yaml_path = f"plugins/yaml/dashboard-{version}-original.yaml"
        if destination_name is None:
            destination_name = f"dashboard-{version}.yaml"
        super().__init__(cluster, inventory, plugin_name, original_yaml_path, destination_name)

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

    def enrich_namespace_kubernetes_dashboard(self, manifest: Manifest):
        key = "Namespace_kubernetes-dashboard"
        rbac = self.inventory['rbac']
        if rbac['admission'] == 'pss' and rbac['pss']['pod-security'] == 'enabled' \
                and rbac['pss']['defaults']['enforce'] == 'restricted':
            self.assign_default_pss_labels(manifest, key, 'baseline')

    def enrich_deployment_kubernetes_dashboard(self, manifest: Manifest):
        key = "Deployment_kubernetes-dashboard"
        self.enrich_image_for_container(manifest, key,
            plugin_service='dashboard', container_name='kubernetes-dashboard', is_init_container=False)

        self.enrich_node_selector(manifest, key, plugin_service='dashboard')
        self.enrich_tolerations(manifest, key, plugin_service='dashboard', override=True)

    def enrich_deployment_dashboard_metrics_scraper(self, manifest: Manifest):
        key = "Deployment_dashboard-metrics-scraper"
        self.enrich_image_for_container(manifest, key,
            plugin_service='metrics-scraper', container_name='dashboard-metrics-scraper', is_init_container=False)

        self.enrich_node_selector(manifest, key, plugin_service='metrics-scraper')
        self.enrich_tolerations(manifest, key, plugin_service='metrics-scraper', override=True)


class V2_5_X_DashboardManifestProcessor(DashboardManifestProcessor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def enrich_deployment_dashboard_metrics_scraper(self, manifest: Manifest):
        key = "Deployment_dashboard-metrics-scraper"
        source_yaml = manifest.get_obj(key, patch=True)
        template_spec: dict = source_yaml['spec']['template']['spec']
        del template_spec['securityContext']
        self.log.verbose(f"The 'securityContext' property has been removed from 'spec.template.spec' in the {key}")
        super().enrich_deployment_dashboard_metrics_scraper(manifest)


def get_dashboard_manifest_processor(cluster: KubernetesCluster, inventory: dict, **kwargs):
    version: str = inventory['plugins']['kubernetes-dashboard']['version']
    if '.'.join(version.split('.')[0:2]) == 'v2.5':
        return V2_5_X_DashboardManifestProcessor(cluster, inventory, **kwargs)

    return DashboardManifestProcessor(cluster, inventory, **kwargs)
