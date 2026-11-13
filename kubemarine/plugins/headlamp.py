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

import os
from typing import Optional

import yaml
from kubemarine import plugins
from kubemarine.core import utils, summary
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.yaml_merger import default_merger

ERROR_SAME_HOSTNAME = ("Plugins 'headlamp' and 'kubernetes-dashboard' are both set to be installed "
                       "with the same hostname {hostname!r}. "
                       "Please specify different 'hostname' for one of the plugins.")


@enrichment(EnrichmentStage.FULL)
def verify_inventory(cluster: KubernetesCluster) -> None:
    inventory_plugins = cluster.inventory["plugins"]
    headlamp_plugin = inventory_plugins["headlamp"]
    dashboard_plugin = inventory_plugins["kubernetes-dashboard"]
    if not headlamp_plugin["install"] or not dashboard_plugin["install"]:
        return

    hostname = headlamp_plugin["hostname"]
    if hostname == dashboard_plugin["hostname"]:
        raise Exception(ERROR_SAME_HOSTNAME.format(hostname=hostname))


def get_chart_path(chart_version: str) -> str:
    return utils.get_internal_resource_path(f"plugins/charts/headlamp-{chart_version}")


def get_image_version(chart_version: str) -> str:
    chart_manifest_path = os.path.join(get_chart_path(chart_version), "Chart.yaml")
    if not os.path.isfile(chart_manifest_path):
        raise Exception(f"Headlamp chart of version {chart_version} is not found at {chart_manifest_path}. "
                        f"The chart should be downloaded manually.")

    chart_manifest = utils.load_yaml(chart_manifest_path)
    # The chart uses "v{appVersion}" image tag by default
    return f"v{chart_manifest['appVersion']}"


def _resolve_registry(headlamp_plugin: dict, registry_key: str, default: str) -> str:
    """
    Registry resolution order: specific registry (e.g. `headlampRegistry`),
    then `installation.registry` (also enriched from `plugin_defaults`), then the default.
    """
    return headlamp_plugin[registry_key] or headlamp_plugin["installation"].get("registry") or default


def _with_registry(registry: str, image: str) -> str:
    return f"{registry}/{image}" if registry else image


def get_url(inventory: dict) -> Optional[str]:
    """
    :return: URL of Headlamp UI, or None if neither Ingress nor HTTPRoute is created.
    """
    headlamp_plugin = inventory["plugins"]["headlamp"]
    nginx_installed = inventory["plugins"]["nginx-ingress-controller"]["install"]
    envoy_plugin = inventory["plugins"]["envoy-gateway"]
    if not nginx_installed and not envoy_plugin["install"]:
        return None

    https = nginx_installed or (envoy_plugin["externalGateway"]["certificate"]["cert"] != ""
                                and envoy_plugin["externalGateway"]["certificate"]["key"] != "")
    return f"{'https' if https else 'http'}://{headlamp_plugin['hostname']}"


def schedule_summary_report(cluster: KubernetesCluster) -> None:
    url = get_url(cluster.inventory)
    if url is not None:
        summary.schedule_report(cluster.context, summary.SummaryItem.HEADLAMP_URL, url)


def apply_headlamp_chart(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    headlamp_plugin = inventory["plugins"]["headlamp"]
    chart_version = headlamp_plugin["version"]
    headlamp_registry = _resolve_registry(headlamp_plugin, "headlampRegistry", "ghcr.io")
    debug_image = _with_registry(_resolve_registry(headlamp_plugin, "debugRegistry", ""),
                                 headlamp_plugin["debugImage"])
    hostname = headlamp_plugin["hostname"]

    helm_plugin_config = {
        "chart_path": get_chart_path(chart_version),
        "values": {
            "image": {
                "registry": headlamp_registry,
            },
            "config": {
                "nodeShellImage": debug_image,
                "podDebugImage": debug_image,
                "nodeShellNamespace": "kube-system",
                "staticPlugins": {
                    "enabled": False,
                },
            },
            "securityContext": {
                "runAsNonRoot": True,
                "privileged": False,
                "runAsUser": 100,
                "runAsGroup": 101,
                "allowPrivilegeEscalation": False,
                "capabilities": {
                    "drop": ["ALL"],
                },
                "seccompProfile": {
                    "type": "RuntimeDefault",
                },
            },
            "nodeSelector": {
                "kubernetes.io/os": "linux",
            },
            "resources": {
                "requests": {
                    "cpu": "100m",
                    "memory": "256Mi",
                },
                "limits": {
                    "memory": "256Mi",
                },
            },
        },
        "namespace": headlamp_plugin["namespace"],
        "release": headlamp_plugin["releaseName"],
        "take_ownership": True,
    }

    if inventory["plugins"]["nginx-ingress-controller"]["install"]:
        helm_plugin_config["values"]["ingress"] = {
            "enabled": True,
            "ingressClassName": "nginx",
            "annotations": {
                # Avoid duplicating the route if Envoy Gateway is installed, since HTTPRoute is created separately
                "gateway-api-converter.netcracker.com/ignore": "true",
            },
            "hosts": [{
                "host": hostname,
                "paths": [{"path": "/", "type": "Prefix"}],
            }],
            # Since certificate is not provided, default controller certificate is used
            "tls": [{"hosts": [hostname]}],
        }

    envoy_plugin = inventory["plugins"]["envoy-gateway"]
    if envoy_plugin["install"]:
        helm_plugin_config["values"]["httpRoute"] = {
            "enabled": True,
            "parentRefs": [{
                "name": "default-external-gateway",
                "namespace": envoy_plugin["namespace"],
            }],
            "hostnames": [hostname],
        }

    helm_plugin_config["values"] = default_merger.merge(helm_plugin_config["values"], headlamp_plugin["values"])
    utils.dump_file(cluster.context, yaml.dump(helm_plugin_config["values"]), "headlamp-values.yaml",
                    dump_location=True)
    plugins.apply_helm(cluster=cluster, config=helm_plugin_config)
