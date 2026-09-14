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
from typing import List

from jinja2 import Template

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup

@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    zram_list: List[dict] = cluster.inventory.get('services', {}).get('zram', [])
    if not zram_list:
        return

    need_zram_module = set()
    for item in zram_list:
        if "size" not in item:
            item["size"] = 1024
        if "groups" not in item and "nodes" not in item:
            item["groups"] = ["control-plane", "worker"]
            item["nodes"] = []

        group = cluster.create_group_from_groups_nodes_names(item.get('groups') or [], item.get('nodes') or [])
        if item["state"] == "present":
            need_zram_module.update(group.get_nodes_names())
        else:
            need_zram_module.difference_update(group.get_nodes_names())

        all_nodes_names = cluster.nodes['all'].get_nodes_names()
        unknown_nodes = set(item['nodes']) - set(all_nodes_names)
        if unknown_nodes:
            cluster.log.warning(
                f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                f"provided for zram path {item['path']!r}.")

    if need_zram_module:
        for _, os_modules in cluster.inventory["services"]["modprobe"].items():
            to_add_zram = True
            for module in os_modules:
                if module == "zram" or ("modulename" in module and module["modulename"] == "zram"):
                    to_add_zram = False
                    break
            if to_add_zram:
                os_modules.append({
                    "modulename": "zram",
                    "nodes": list(need_zram_module), 
                })


def check_zram(group: NodeGroup) -> List[str]:
    """
    Return a list of human-readable error strings for ZRAM mount issues.
    """
    cluster: KubernetesCluster = group.cluster
    if not cluster.inventory.get('services', {}).get('zram'):
        cluster.log.debug("Skipped - no zram items defined in config file")
        return []
    
    errors = []
    zram_output = group.sudo("zramctl -n -o MOUNTPOINT,DISKSIZE --bytes", warn=True)
    for node in group.get_ordered_members_list():
        expected_mounts = _get_expected_mounts(cluster, node)
        if not expected_mounts:
            continue

        actual_mounts = _get_actual_mounts(zram_output[node.get_host()].stdout)
        for path, cfg in expected_mounts.items():
            if cfg["state"] == "absent":
                if path in actual_mounts:
                    errors.append(f"{node.get_node_name()}: {path!r} is still mounted")
            else:
                if path not in actual_mounts:
                    errors.append(f"{node.get_node_name()}: {path!r} is not mounted")
                elif cfg["size"] != actual_mounts[path]:
                    errors.append(f"{node.get_node_name()}: {path!r} expected size {cfg['size']}, "
                                f"but got {actual_mounts[path]}")
    return errors


def setup_zram(group: NodeGroup) -> bool:
    """
    Configures ZRAM on nodes and returns true if nodes reboot is required.
    """

    cluster: KubernetesCluster = group.cluster
    logger = cluster.log
    is_changed = False
    zram_list = cluster.inventory.get('services', {}).get('zram', [])
    for idx, zram_item in enumerate(zram_list):
        item_group = cluster.create_group_from_groups_nodes_names(zram_item.get('groups') or [], zram_item.get('nodes') or [])
        item_group = item_group.intersection_group(group)
        unit_name = f'zram-setup-{zram_item["path"].strip("/").replace("/", "-")}.service'
        unit_destination = f'/etc/systemd/system/{unit_name}'

        if zram_item["state"] == "present":
            logger.debug(f"Setting up zram for path {zram_item['path']} on {item_group.get_nodes_names()}")
            unit_content = _render_unit(zram_item)
            item_group.put(io.StringIO(unit_content), unit_destination, sudo=True)
            utils.dump_file(cluster, unit_content, f'zram/{idx}-{unit_name}')
            logger.debug(item_group.sudo("systemctl daemon-reload"))
            # do not enable immediately, since it may not work without reboot
            logger.debug(item_group.sudo(f"systemctl enable {unit_name}"))
        elif zram_item["state"] == "absent":
            logger.debug(f"Removing zram for path {zram_item['path']} on {item_group.get_nodes_names()}")
            logger.debug(item_group.sudo(f"systemctl disable {unit_name}", warn=True))
            logger.debug(item_group.sudo(f"rm -f {unit_destination}"))
            logger.debug(item_group.sudo("systemctl daemon-reload"))
        is_changed = True

    return is_changed


def _render_unit(item: dict) -> str:
    template_content = utils.read_internal('templates/zram-setup.service.j2')

    return Template(template_content).render(
        path=item['path'],
        size=item.get('size', ''),
    )

def _get_expected_mounts(cluster: KubernetesCluster, node: NodeGroup) -> dict:
    """
    Returns dict {path: {state, sizeMiB}} with expected ZRAM mounts
    """
    zram_list = cluster.inventory.get('services', {}).get('zram', [])
    expected = {}
    for item in zram_list:
        groups = item.get('groups')
        nodes = item.get('nodes')
        group = cluster.create_group_from_groups_nodes_names(groups or [], nodes or [])
        if group.has_node(node.get_node_name()):
            expected[item["path"]] = {
                "state": item["state"],
                "size": item["size"]
            }
    return expected

def _get_actual_mounts(stdout: str) -> dict:
    """
    Returns dict {path: sizeMiB} with actual ZRAM mounts paths and their sizes
    """
    actual = {}
    for line in stdout.splitlines():
        words = line.split()
        actual[words[0]] = int(int(words[1])/(1024*1024))
    return actual