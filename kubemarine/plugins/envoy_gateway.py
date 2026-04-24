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

import base64
import os
import yaml
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine import plugins, haproxy
from kubemarine.core.yaml_merger import default_merger

ERROR_CERT_RENEW_NOT_INSTALLED = "Certificates can not be renewed for envoy gateway plugin since it is not installed"

@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:    
    # We override priority from 1 to 2, to make envoy install after nginx if envoy is target_backend.
    # This is required to make sure nginx frees hostPorts
    if haproxy.get_target_backend(cluster.inventory) == "envoy":
        cluster.inventory["plugins"]["envoy-gateway"]["installation"]["priority"] = 2

@enrichment(EnrichmentStage.PROCEDURE, procedures=['cert_renew'])
def cert_renew_enrichment(cluster: KubernetesCluster) -> None:
    # check that renewal is required for envoy
    procedure_envoy_cert = cluster.procedure_inventory.get("envoy-gateway", {})
    if not procedure_envoy_cert:
        return

    # update certificates in inventory
    cluster.inventory.setdefault("plugins", {}).setdefault("envoy-gateway", {}) \
        .setdefault("externalGateway", {})["certificate"] = utils.deepcopy_yaml(procedure_envoy_cert)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['cert_renew'])
def verify_cert_renew(cluster: KubernetesCluster) -> None:
    procedure_envoy_cert = cluster.procedure_inventory.get("envoy-gateway", {})
    # check that renewal is possible
    if procedure_envoy_cert and not cluster.inventory["plugins"]["envoy-gateway"]["install"]:
        raise Exception(ERROR_CERT_RENEW_NOT_INSTALLED)
    
def get_images_versions(chart_version: str) -> dict[str, str]:
    values = utils.load_yaml(utils.get_internal_resource_path(
        f"plugins/charts/envoy-gateway-{chart_version}/values.yaml"
    ))
    crValues = utils.load_yaml(utils.get_internal_resource_path(
        f"plugins/charts/envoy-gateway-cr-{chart_version}/values.yaml"
    ))
    return {
        "envoyGateway": values["global"]["images"]["envoyGateway"]["image"].split(":")[-1],
        "envoy": crValues["global"]["images"]["envoy"]["image"].split(":")[-1],
        "kubectl": crValues["global"]["images"]["kubectl"]["image"].split(":")[-1],
        "ratelimit": values["global"]["images"]["ratelimit"]["image"].split(":")[-1]   
    }

def apply_envoy_chart(cluster: KubernetesCluster) -> None:
    envoy_plugin = cluster.inventory["plugins"]["envoy-gateway"]
    chart_version = envoy_plugin["version"]
    chart_values = utils.load_yaml(
        utils.get_internal_resource_path(f"plugins/charts/envoy-gateway-{chart_version}/values.yaml")
    )
    
    envoy_gateway_image = chart_values["global"]["images"]["envoyGateway"]["image"]
    ratelimit_image = chart_values["global"]["images"]["ratelimit"]["image"]
    if "registry" in envoy_plugin["installation"]:
        registry = envoy_plugin["installation"]["registry"]
        envoy_gateway_image = f"{registry}/{envoy_gateway_image}"
        ratelimit_image = f"{registry}/{ratelimit_image}"

    helm_plugin_config = {
        "chart_path": utils.get_internal_resource_path(f"plugins/charts/envoy-gateway-{chart_version}"),
        "values": {
            "gateway-helm": {
                "config": {
                    "envoyGateway": {
                        "extensionApis": {
                            "enableBackend": True,
                            "enableEnvoyPatchPolicy": True,
                        },
                    },
                },
            },
            "global": {
                "images": {
                    "envoyGateway": {
                        "image": envoy_gateway_image,
                    },
                    "ratelimit": {
                        "image": ratelimit_image,
                    }
                },
            },
        },
        "namespace": envoy_plugin["namespace"],
        "release": envoy_plugin["releaseName"],
    }

    # We apply CRDs separately from chart, because Helm does not support CRD upgrade.
    # We also use server-side apply to avoid issues with annotation size.
    crds_directory = utils.get_internal_resource_path(f"plugins/charts/envoy-gateway-{chart_version}/charts/gateway-helm/crds")
    for dirpath, _, filenames in os.walk(crds_directory):
        for file in filenames:
            plugins.apply_source(cluster=cluster, config={
                "source": os.path.join(dirpath, file),
                "destination": f"/tmp/envoy-gateway-crds/{file}",
                "apply_command": f"kubectl apply --server-side -f /tmp/envoy-gateway-crds/{file}",
            })

    helm_plugin_config["values"] = default_merger.merge(helm_plugin_config["values"], envoy_plugin["valuesOverride"])
    utils.dump_file(cluster.context, yaml.dump(helm_plugin_config["values"]), "envoy-values.yaml", dump_location=True)
    plugins.apply_template(cluster=cluster, config={
        "source": utils.get_internal_resource_path(f"templates/plugins/envoy-gateway-namespace.yaml.j2")
    })
    plugins.apply_helm(cluster=cluster, config=helm_plugin_config)

def apply_cr_chart(cluster: KubernetesCluster) -> None:
    envoy_plugin = cluster.inventory["plugins"]["envoy-gateway"]
    chart_version = envoy_plugin["version"]
    chart_values = utils.load_yaml(
        utils.get_internal_resource_path(f"plugins/charts/envoy-gateway-cr-{chart_version}/values.yaml")
    )
    
    envoy_image = chart_values["global"]["images"]["envoy"]["image"]
    kubectl_image = chart_values["global"]["images"]["kubectl"]["image"]
    if "registry" in envoy_plugin["installation"]:
        registry = envoy_plugin["installation"]["registry"]
        envoy_image = f"{registry}/{envoy_image}"
        if envoy_plugin["kubectlRegistry"] == "":
            kubectl_image = kubectl_image.replace("ghcr.io", registry)
    if envoy_plugin["kubectlRegistry"] != "":
        kubectl_image = kubectl_image.replace("ghcr.io", envoy_plugin["kubectlRegistry"])

    helm_plugin_config = {
        "chart_path": utils.get_internal_resource_path(f"plugins/charts/envoy-gateway-cr-{chart_version}"),
        "values": {
            "global": {
                "images": {
                    "envoy": {
                        "image": envoy_image,
                    },
                    "kubectl": {
                        "image": kubectl_image,
                    }
                },
            },
            "gatewayClasses": {
                "external": {
                    "envoyService": {
                        "type": "ClusterIP",
                        "name": "external-gateway",
                    },
                    "envoyDeployment": {
                        "daemonset": True,
                        "name": "envoy-external-gateway",
                    },
                },
            },
            "defaultGateways": {
                "internal": {
                    "enabled": False
                },
                "external": {
                    "ctpName": "external-client-traffic-policy",
                    "ctpSpec": {
                        "headers": {
                            "withUnderscoresAction": "Allow",
                            "earlyRequestHeaders": {
                                "add": [
                                    {
                                        "name": "X-Forwarded-Host",
                                        "value": '%REQ(Host)%',
                                    }
                                ],
                            },
                        },
                    },
                },
            },
        },
        "namespace": envoy_plugin["namespace"],
        "release": envoy_plugin["crReleaseName"],
    }

    if envoy_plugin["externalGateway"]["certificate"]["cert"] != "" \
        and envoy_plugin["externalGateway"]["certificate"]["key"] != "":

        helm_plugin_config["values"]["defaultGateways"]["external"]["httpsPort"] = 443
        helm_plugin_config["values"]["defaultGateways"]["external"]["secret"] = {
            "create": True,
            "crt": base64.b64encode(envoy_plugin["externalGateway"]["certificate"]["cert"].encode("utf-8")).decode("ascii"),
            "key": base64.b64encode(envoy_plugin["externalGateway"]["certificate"]["key"].encode("utf-8")).decode("ascii"),
        }

    if haproxy.get_target_backend(cluster.inventory) == "envoy":
        targetPorts = cluster.inventory["services"]["loadbalancer"]["target_ports"]
        helm_plugin_config["values"]["defaultGateways"]["external"]["proxyProtocol"] = True
        helm_plugin_config["values"]["defaultGateways"]["external"]["hostPorts"] = True
        helm_plugin_config["values"]["defaultGateways"]["external"]["httpHostPort"] = targetPorts["http"]
        helm_plugin_config["values"]["defaultGateways"]["external"]["httpsHostPort"] = targetPorts["https"]
    else:
        # If HAProxy is not used in front of Envoy, then we should not enable proxyProtocol
        helm_plugin_config["values"]["defaultGateways"]["external"]["proxyProtocol"] = False

    if envoy_plugin["externalGateway"]["hostPorts"]["http"] != 0 \
        and envoy_plugin["externalGateway"]["hostPorts"]["https"] != 0:
        
        helm_plugin_config["values"]["defaultGateways"]["external"]["hostPorts"] = True
        helm_plugin_config["values"]["defaultGateways"]["external"]["httpHostPort"] = \
            envoy_plugin["externalGateway"]["hostPorts"]["http"]
        helm_plugin_config["values"]["defaultGateways"]["external"]["httpsHostPort"] = \
            envoy_plugin["externalGateway"]["hostPorts"]["https"]

    helm_plugin_config["values"] = default_merger.merge(helm_plugin_config["values"], envoy_plugin["crValuesOverride"])
    utils.dump_file(cluster.context, yaml.dump(helm_plugin_config["values"]), "envoy-cr-values.yaml", dump_location=True)
    plugins.apply_helm(cluster=cluster, config=helm_plugin_config)
