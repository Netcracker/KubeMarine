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
from typing import List, Union

from jinja2 import Template

from kubemarine import system
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup, CollectorCallback

@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    zram_list: List[dict] = cluster.inventory.get('services', {}).get('zram', [])
    for item in zram_list:
        if "size" not in item:
            item["size"] = "1G"
        if "groups" not in item and "nodes" not in item:
            item["groups"] = ["control-plane", "worker"]
            item["nodes"] = []

        all_nodes_names = cluster.nodes['all'].get_nodes_names()
        unknown_nodes = set(item['nodes']) - set(all_nodes_names)
        if unknown_nodes:
            cluster.log.warning(
                f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                f"provided for zram path {item['path']!r}.")


def get_applicable_items(cluster: KubernetesCluster, node: NodeGroup,
                         zram_list: List[dict] = None) -> List[dict]:
    if zram_list is None:
        zram_list = cluster.inventory.get('services', {}).get('zram', [])
    applicable = []
    for item in zram_list:
        groups: Union[List[str], None] = item.get('groups')
        nodes: Union[List[str], None] = item.get('nodes')
        group = cluster.create_group_from_groups_nodes_names(groups or [], nodes or [])
        if group.has_node(node.get_node_name()):
            applicable.append(item)
    return applicable


def _render_unit(item: dict) -> str:
    template_content = utils.read_internal('templates/zram-setup.service.j2')

    return Template(template_content).render(
        path=item['path'],
        size=item.get('size', ''),
    )


def _parse_mounts(mounts_output: str) -> dict:
    """Parse /proc/mounts into {mountpoint: fstype}."""
    result = {}
    for line in mounts_output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            result[parts[1]] = parts[2]
    return result


def is_zram_configured(group: NodeGroup, zram_list: List[dict] = None) -> bool:
    cluster: KubernetesCluster = group.cluster
    results = group.sudo("cat /proc/mounts")

    # TODO: rework
    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node, zram_list)
        if not applicable:
            continue
        host = node.get_host()
        mounts = _parse_mounts(results[host].stdout)
        for item in applicable:
            if item['state'] is "present" and item['path'].rstrip('/') not in mounts:
                cluster.log.debug(f"Mount path {item['path']!r} not found in /proc/mounts on {host}")
                return False
            if item['state'] is "absent" and item['path'].rstrip('/') in mounts:
                cluster.log.debug(f"Mount path {item['path']!r} is still present in /proc/mounts on {host}")
                return False

    return True


def check_mounts(group: NodeGroup, zram_list: List[dict] = None) -> List[str]:
    """Return a list of human-readable error strings for missing or wrong-type mounts."""
    cluster: KubernetesCluster = group.cluster

    mounts_collector = CollectorCallback(cluster)
    zramctl_collector = CollectorCallback(cluster)
    defer = group.new_defer()
    # TODO: fix
    defer.sudo("cat /proc/mounts", callback=mounts_collector)
    defer.sudo("zramctl --output-all", warn=True, callback=zramctl_collector)
    defer.flush()

    errors = []

    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node, zram_list)
        if not applicable:
            continue
        host = node.get_host()
        node_name = node.get_node_name()
        mounts = _parse_mounts(mounts_collector.result[host].stdout)
        zramctl_output = zramctl_collector.result[host].stdout

        for item in applicable:
            mount_path = item['path'].rstrip('/')
            expected_type = item.get('type', '')
            if mount_path not in mounts:
                errors.append(f"{node_name}: {mount_path!r} is not mounted")
            elif expected_type and mounts[mount_path] != expected_type:
                errors.append(
                    f"{node_name}: {mount_path!r} has fstype {mounts[mount_path]!r}, expected {expected_type!r}")

            if item['device'].startswith('/dev/zram') and mount_path not in zramctl_output:
                errors.append(f"{node_name}: {mount_path!r} not found in zramctl output")

    return errors


def setup_zram(group: NodeGroup, zram_list: List[dict] = None) -> bool:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log

    for node in group.get_ordered_members_list():
        applicable = get_applicable_items(cluster, node, zram_list)
        if not applicable:
            continue

        for item in applicable:
            unit_name = f'zram-setup{item["path"].replace("/", "-")}'
            unit_destination = f'/etc/systemd/system/{unit_name}.service'
            if item["state"] == "present":
                unit_content = _render_unit(item)
                logger.debug(f"Setting up zram for path {item["path"]} on {node.get_node_name()}")
                node.put(io.StringIO(unit_content), unit_destination, backup=True, sudo=True)
                utils.dump_file(cluster, unit_content, f'fsmount/{unit_name}_{node.get_node_name()}')
                node.sudo("systemctl daemon-reload")
                node.sudo(f"systemctl enable {unit_name}")
            elif item["state"] == "absent":
                node.sudo(f"systemctl disable {unit_name}")
                node.sudo(f"rm -f {unit_destination}")
                node.sudo("systemctl daemon-reload")

    cluster.schedule_cumulative_point(system.reboot_nodes)      