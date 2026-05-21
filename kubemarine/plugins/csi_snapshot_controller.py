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

import io
import yaml
from kubemarine import plugins
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.yaml_merger import default_merger

def apply_snapshot_controller_chart(cluster: KubernetesCluster) -> None:
    snapshot_controller_plugin = cluster.inventory["plugins"]["csi-snapshot-controller"]
    chart_version = snapshot_controller_plugin["version"]

    helm_plugin_config = {
        "chart_path": utils.get_internal_resource_path(f"plugins/charts/csi-snapshot-controller-{chart_version}"),
        "namespace": snapshot_controller_plugin["namespace"],
        "release": snapshot_controller_plugin["releaseName"],
        "take_ownership": True,
    }

    if "registry" in snapshot_controller_plugin["installation"]:
        registry = snapshot_controller_plugin["installation"]["registry"]
        helm_plugin_config["values"] = {
            "controller": {
                "image": {
                    "repository": f"{registry}/sig-storage/snapshot-controller"
                },
            }
        }

    helm_plugin_config["values"] = default_merger.merge(helm_plugin_config["values"], snapshot_controller_plugin["values"])
    utils.dump_file(
        cluster.context, 
        yaml.dump(helm_plugin_config["values"]), "csi-snapshot-controller-values.yaml", 
        dump_location=True
    )
    plugins.apply_helm(cluster=cluster, config=helm_plugin_config)


def apply_additional_resources(cluster: KubernetesCluster) -> None:
    snapshot_controller_plugin = cluster.inventory["plugins"]["csi-snapshot-controller"]
    if not snapshot_controller_plugin["additionalResources"]:
        cluster.log.debug(f"Additional resources are not specified, skipping")
        return
    
    destination = '/etc/kubernetes/csi-snapshot-controller-additional-resources.yaml'
    config = {
        "source": io.StringIO(snapshot_controller_plugin["additionalResources"]),
        "destination": destination,
        "do_render": False
    }
    plugins.apply_source(cluster, config)

