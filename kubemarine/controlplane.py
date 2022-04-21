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

def controlplane_node_enrichment(inventory, cluster):
    """
    Enriched inventory should have both the 'master' and the 'control-plane' roles for backward compatibility
    The 'control-plane' role is used instead of 'master' role since Kubernetes v1.24
    """
    for node in inventory["nodes"]:
        if "master" in node["roles"] and "control-plane" not in node["roles"]:
            cluster.log.debug("'control-plane' role will be added for nodes with 'master' role")
            cluster.log.warning("Node with name: %s has legacy role 'master'. Please use 'control-plane' instead" % node["name"])
            node_id = inventory["nodes"].index(node)
            inventory["nodes"][node_id]["roles"].append("control-plane")
            cluster.supported_roles.append("cl-patched")
            inventory["nodes"][node_id]["roles"].append("cl-patched")
        if "control-plane" in node["roles"] and "master" not in node["roles"]:
            cluster.log.debug("'master' role will be added for nodes with 'control-plane' role")
            node_id = inventory["nodes"].index(node)
            inventory["nodes"][node_id]["roles"].append("master")
            cluster.supported_roles.append("m-patched")
            inventory["nodes"][node_id]["roles"].append("m-patched")

    return inventory

def controlplane_finalize_inventory(cluster, inventory):
    """
    Delete 'control-plane'/'master' role before inventory saving if 'control-plane'/'master' is not set in 'cluster.yaml'
    """
    for i, node in enumerate(inventory['nodes']):
        if 'control-plane' in node['roles'] and 'cl-patched' in node['roles']:
            inventory['nodes'][i]['roles'].remove('control-plane')
            inventory['nodes'][i]['roles'].remove('cl-patched')
        if 'master' in node['roles'] and 'm-patched' in node['roles']:
            inventory['nodes'][i]['roles'].remove('master')
            inventory['nodes'][i]['roles'].remove('m-patched')
