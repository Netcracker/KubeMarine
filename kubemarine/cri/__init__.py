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
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import RunnersGroupResult, NodeGroup
from kubemarine.cri import docker, containerd

ERROR_FORBIDDEN_CRI_SECTION = "{key} is not used, please remove {value} config from `services.cri` section"


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    cri_impl = get_cri_impl(inventory)

    if cri_impl == "docker":
        forbidden_cri_sections = {"containerd": ["containerdConfig", "containerdRegistriesConfig"]}
        del inventory['services']['cri']['containerdConfig']
    else:
        forbidden_cri_sections = {"docker": ["dockerConfig"]}
        del inventory['services']['cri']['dockerConfig']

    for key, sections in forbidden_cri_sections.items():
        for value in sections:
            if value in cluster.raw_inventory.get('services', {}).get('cri', {}):
                raise Exception(ERROR_FORBIDDEN_CRI_SECTION.format(key=key, value=value))

    # Enrich containerdConfig
    if cri_impl == "containerd":
        containerd.enrich_inventory(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def enrich_upgrade_inventory(cluster: KubernetesCluster) -> None:
    cri_impl = get_cri_impl(cluster.previous_inventory)
    if cri_impl == "containerd":
        containerd.enrich_upgrade_inventory(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def verify_upgrade_inventory(cluster: KubernetesCluster) -> None:
    cri_impl = get_cri_impl(cluster.previous_inventory)
    if cri_impl == "containerd":
        containerd.verify_upgrade_inventory(cluster)


def get_cri_impl(inventory: dict) -> str:
    cri_impl: str = inventory['services']['cri']['containerRuntime']
    return cri_impl


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
