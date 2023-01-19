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
from kubemarine.core.cluster import KubernetesCluster


def controlplane_node_enrichment(inventory: dict, cluster: KubernetesCluster):
    """
    Enriched inventory should have both the 'master' and the 'control-plane' roles for backward compatibility
    The 'control-plane' role is used instead of 'master' role since Kubernetes v1.24
    """
    for node in inventory["nodes"]:
        node_info = node.get('name', cluster.get_access_address_from_node(node))
        if "master" in node["roles"] and "control-plane" not in node["roles"]:
            cluster.log.debug(f"The 'control-plane' role will be added for {node_info}")
            cluster.log.warning(f"Node {node_info} has legacy role 'master'. "
                                f"Please use 'control-plane' instead.")
            node["roles"].append("control-plane")
        if "control-plane" in node["roles"] and "master" not in node["roles"]:
            cluster.log.debug(f"The 'master' role will be added for {node_info}")
            node["roles"].append("master")

    return inventory


def controlplane_finalize_inventory(cluster, inventory):
    """
    Delete 'control-plane' and 'master' roles before inventory saving if they are not set in 'cluster.yaml'
    """
    # remove 'master' role from inventory before dump
    for node in inventory["nodes"]:
        if 'master' in node["roles"]:
            node_info = node.get('name', cluster.get_access_address_from_node(node))
            cluster.log.debug(f"The 'master' role will be removed for {node_info} node before saving")
            node["roles"].remove("master")

    return inventory
