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
from kubemarine.cri import containerd


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    containerd.enrich_inventory(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def enrich_upgrade_inventory(cluster: KubernetesCluster) -> None:
    containerd.enrich_upgrade_inventory(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def verify_upgrade_inventory(cluster: KubernetesCluster) -> None:
    containerd.verify_upgrade_inventory(cluster)


def install(group: NodeGroup) -> RunnersGroupResult:
    return containerd.install(group)


def configure(group: NodeGroup) -> RunnersGroupResult:
    return containerd.configure(group)


def prune(group: NodeGroup) -> RunnersGroupResult:
    return containerd.prune(group)
