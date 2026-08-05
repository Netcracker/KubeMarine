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

import io
import os
from typing import List, Union

from jinja2 import Template

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    fsmount_list: List[dict] = cluster.inventory.get('services', {}).get('fsmount', [])
    for i, item in enumerate(fsmount_list):
        path: List[Union[str, int]] = ['services', 'fsmount', i]

        if item.get('groups') is None and item.get('nodes') is None:
            continue

        preparation_script = item.get('preparation_script')
        if preparation_script is not None:
            ext_path = utils.get_external_resource_path(preparation_script)
            if not os.path.isfile(ext_path) and not os.path.isfile(utils.get_internal_resource_path(preparation_script)):
                raise Exception(
                    f"'preparation_script' file {preparation_script!r} not found "
                    f"for fsmount item at {utils.pretty_path(path)}")

        if item.get('nodes') is not None:
            all_nodes_names = cluster.nodes['all'].get_nodes_names()
            unknown_nodes = set(item['nodes']) - set(all_nodes_names)
            if unknown_nodes:
                cluster.log.warning(
                    f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                    f"provided for fsmount item {item['name']!r}.")


def get_applicable_items(cluster: KubernetesCluster, node: NodeGroup) -> List[dict]:
    fsmount_list: List[dict] = cluster.inventory.get('services', {}).get('fsmount', [])
    applicable = []
    for item in fsmount_list:
        groups: Union[List[str], None] = item.get('groups')
        nodes: Union[List[str], None] = item.get('nodes')
        group = cluster.create_group_from_groups_nodes_names(groups or [], nodes or [])
        if group.has_node(node.get_node_name()):
            applicable.append(item)
    return applicable


def _render_unit(item: dict) -> str:
    template_source = item['template']['source']
    ext_path = utils.get_external_resource_path(template_source)
    if os.path.isfile(ext_path):
        template_content = utils.read_external(template_source)
    else:
        template_content = utils.read_internal(template_source)

    return Template(template_content).render(
        name=item['name'],
        device=item['device'],
        path=item['path'],
        size=item.get('size', ''),
        type=item.get('type', ''),
    )


def _parse_mounts(mounts_output: str) -> dict:
    """Parse /proc/mounts into {mountpoint: fstype}."""
    result = {}
    for line in mounts_output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            result[parts[1]] = parts[2]
    return result


def is_mounted(group: NodeGroup) -> bool:
    cluster: KubernetesCluster = group.cluster
    results = group.sudo("cat /proc/mounts")

    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node)
        if not applicable:
            continue
        host = node.get_host()
        mounts = _parse_mounts(results[host].stdout)
        for item in applicable:
            if item['path'].rstrip('/') not in mounts:
                cluster.log.debug(f"Mount path {item['path']!r} not found in /proc/mounts on {host}")
                return False

    return True


def check_mounts(group: NodeGroup) -> List[str]:
    """Return a list of human-readable error strings for missing or wrong-type mounts."""
    cluster: KubernetesCluster = group.cluster
    results = group.sudo("cat /proc/mounts")
    errors = []

    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node)
        if not applicable:
            continue
        host = node.get_host()
        node_name = node.get_node_name()
        mounts = _parse_mounts(results[host].stdout)
        for item in applicable:
            mount_path = item['path'].rstrip('/')
            expected_type = item.get('type', '')
            if mount_path not in mounts:
                errors.append(f"{node_name}: {mount_path!r} is not mounted")
            elif expected_type and mounts[mount_path] != expected_type:
                errors.append(
                    f"{node_name}: {mount_path!r} has fstype {mounts[mount_path]!r}, expected {expected_type!r}")

    return errors


def setup_fsmount(group: NodeGroup) -> bool:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log

    if is_mounted(group):
        logger.debug("Skipped - all required filesystems are already mounted")
        return False

    changed = False
    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node)
        if not applicable:
            continue

        host = node.get_host()
        mounts_output = node.sudo("cat /proc/mounts")[host].stdout

        for item in applicable:
            if item['path'].rstrip('/') in mounts_output:
                logger.debug(f"Skipping fsmount item {item['name']!r} on {node.get_node_name()}: already mounted")
                continue

            preparation_script = item.get('preparation_script')
            if preparation_script:
                logger.debug(f"Running preparation script for fsmount item {item['name']!r} on {node.get_node_name()}")
                ext_path = utils.get_external_resource_path(preparation_script)
                if os.path.isfile(ext_path):
                    script_content = utils.read_external(preparation_script)
                else:
                    script_content = utils.read_internal(preparation_script)
                remote_path = f"/tmp/fsmount_{item['name']}_prep.sh"
                node.put(io.StringIO(script_content), remote_path, sudo=True)
                node.sudo(f"chmod +x {remote_path}")
                prep_result = node.sudo(f"bash {remote_path}", warn=True)
                node.sudo(f"rm -f {remote_path}")
                if prep_result[host].return_code != 0:
                    logger.warning(
                        f"Preparation script for fsmount item {item['name']!r} "
                        f"failed on {node.get_node_name()}, skipping."
                        f"The output is: {prep_result[host]}")
                    continue

            unit_content = _render_unit(item)
            unit_destination = item['template']['destination']
            unit_name = unit_destination.rsplit('/', 1)[-1]
            unit_dir = unit_destination.rsplit('/', 1)[0]

            logger.debug(f"Setting up fsmount item {item['name']!r} on {node.get_node_name()}")
            node.sudo(f"mkdir -p {unit_dir}")
            node.put(io.StringIO(unit_content), unit_destination, backup=True, sudo=True)
            utils.dump_file(cluster, unit_content, f'fsmount/{item["name"]}_{node.get_node_name()}.service')
            node.sudo("systemctl daemon-reload")
            node.sudo(f"systemctl enable --now {unit_name}")
            changed = True

    return changed
