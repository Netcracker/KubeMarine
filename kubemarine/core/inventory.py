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

from typing import List, Dict

from kubemarine.core import utils
from kubemarine.core.cluster import EnrichmentStage, enrichment, KubernetesCluster
from kubemarine.core.yaml_merger import default_merger


@enrichment(EnrichmentStage.PROCEDURE, procedures=['reconfigure'])
def enrich_reconfigure_inventory(cluster: KubernetesCluster) -> None:
    # Do not apply usual merging strategy, always merge and never override.
    # This is because `reconfigure` might support to change only subset of sections allowed during installation.
    # Append reconfiguring patches to the end for them to have priority.
    procedure_patches = cluster.procedure_inventory.get('patches', [])
    if procedure_patches:
        cluster.inventory.setdefault('patches', []).extend(procedure_patches)


@enrichment(EnrichmentStage.FULL)
def verify_inventory_patches(cluster: KubernetesCluster) -> None:
    for i, patch in enumerate(cluster.inventory['patches']):
        if patch.get('nodes') is not None:
            all_nodes_names = cluster.nodes['all'].get_nodes_names()
            unknown_nodes = set(patch['nodes']) - set(all_nodes_names)
            if unknown_nodes:
                # Only warn instead of raising an error to allow remove & add the same node.
                cluster.log.warning(
                    f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                    f"provided for inventory{utils.pretty_path(['patches', i])}. ")


def patch_inventory(cluster: KubernetesCluster, section_names: List[str]) -> None:
    """
    Take nested `section_names` from each inventory patch,
    and merge with nested `section_names` of the main inventory.

    Fill `KubernetesCluster.node_inventory` with the result.

    :param cluster: KubernetesCluster instance
    :param section_names: nested sections of the inventory
    """
    same_configs: Dict[tuple, dict] = {}
    for node in cluster.nodes['all'].get_ordered_members_list():
        patch_ids = []
        for i, patch in enumerate(cluster.inventory['patches']):
            group = cluster.create_group_from_groups_nodes_names(
                patch.get('groups', []), patch.get('nodes', []))

            if group.has_node(node.get_node_name()):
                patch_ids.append(i)

        same_id = tuple(patch_ids)
        if same_id not in same_configs:
            config = utils.deepcopy_yaml(_extract_config(cluster.inventory, section_names))

            for i in same_id:
                nxt = utils.deepcopy_yaml(_extract_config(cluster.inventory['patches'][i], section_names))
                config = default_merger.merge(config, nxt)

            same_configs[same_id] = config

        node_inventory = cluster.nodes_inventory.setdefault(node.get_host(), {})
        config = same_configs[same_id]

        _set_config(node_inventory, section_names, config)


def _extract_config(inventory: dict, section_names: List[str]) -> dict:
    section = inventory
    for name in section_names:
        section = section.get(name, {})

    return section


def _set_config(inventory: dict, section_names: List[str], config: dict) -> None:
    section = inventory
    for name in section_names[:-1]:
        section = section.setdefault(name, {})

    section[section_names[-1]] = config
