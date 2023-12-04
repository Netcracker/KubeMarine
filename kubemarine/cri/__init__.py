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
from typing import Optional

from kubemarine.core import static
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import RunnersGroupResult, NodeGroup
from kubemarine.cri import docker, containerd


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    cri_impl = inventory['services']['cri']['containerRuntime']
    if cluster.context.get("initial_procedure") != "migrate_cri":
        if cri_impl == "docker":
            forbidden_cri_sections = {"containerd": "containerdConfig"}
        else:
            forbidden_cri_sections = {"docker": "dockerConfig"}
        for key, value in forbidden_cri_sections.items():
            if value in cluster.raw_inventory.get('services', {}).get('cri', {}):
                raise Exception(f"{key} is not used, please remove {value} config from `services.cri` section")

    # Enrich containerdConfig
    if cri_impl == "containerd":
        return containerd.enrich_inventory(inventory, cluster)

    return inventory


def enrich_upgrade_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    cri_impl = inventory['services']['cri']['containerRuntime']
    if cri_impl == "containerd":
        return containerd.enrich_upgrade_inventory(inventory, cluster)

    return inventory


def upgrade_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    cri_impl = cluster.inventory['services']['cri']['containerRuntime']
    if cri_impl == "containerd":
        return containerd.upgrade_finalize_inventory(cluster, inventory)

    return inventory


def get_initial_cri_impl(inventory: dict) -> str:
    cri_impl: Optional[str] = inventory.get("services", {}).get("cri", {}).get("containerRuntime")
    if cri_impl is None:
        cri_impl = static.DEFAULTS['services']['cri']['containerRuntime']

    return cri_impl


def remove_invalid_cri_config(cluster: KubernetesCluster, inventory: dict) -> dict:
    if inventory['services']['cri']['containerRuntime'] == 'docker':
        if inventory['services']['cri'].get('containerdConfig'):
            del inventory['services']['cri']['containerdConfig']
    elif inventory['services']['cri'].get('dockerConfig'):
        del inventory['services']['cri']['dockerConfig']

    return inventory


def install(group: NodeGroup) -> RunnersGroupResult:
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return docker.install(group)
    else:
        return containerd.install(group)


def configure(group: NodeGroup) -> RunnersGroupResult:
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return docker.configure(group)
    else:
        return containerd.configure(group)


def prune(group: NodeGroup, all_implementations: bool = False) -> RunnersGroupResult:
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    result = RunnersGroupResult(group.cluster, {})
    if cri_impl == "docker" or all_implementations:
        result = docker.prune(group)

    if cri_impl == "containerd" or all_implementations:
        result = containerd.prune(group)

    return result
