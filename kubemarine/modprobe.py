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
from typing import Tuple, List

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, RunnersGroupResult, DeferredGroup, CollectorCallback

predefined_file_path = "/etc/modules-load.d/predefined.conf"


def enrich_kernel_modules(inventory: dict, cluster: KubernetesCluster) -> dict:
    """
    The method enrich the list of kernel modules ('services.modprobe') according to OS family
    """

    final_nodes = cluster.nodes['all'].get_final_nodes()
    for os_family in ('debian', 'rhel', 'rhel8', 'rhel9'):
        # Remove the section for OS families if no node has these OS families.
        if final_nodes.get_subgroup_with_os(os_family).is_empty():
            del inventory["services"]["modprobe"][os_family]

    return inventory


def generate_config(node: DeferredGroup) -> str:
    cluster: KubernetesCluster = node.cluster
    config = ''
    modprobe_config: List[str] = cluster.inventory['services']['modprobe'][node.get_nodes_os()]
    for module_name in modprobe_config:
        config += module_name + "\n"

    return config


def setup_modprobe(group: NodeGroup) -> bool:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log
    group_os_family = group.get_nodes_os()

    is_valid, is_config_valid, result = is_modprobe_valid(group)

    if is_valid and is_config_valid:
        logger.debug("Skipped - all necessary kernel modules are presented")
        logger.debug(result)
        return False

    defer = group.new_defer()
    for node in defer.get_ordered_members_list():
        config = generate_config(node)
        raw_config = config.replace('\n', ' ')

        logger.debug("Uploading config...")
        dump_filename = 'modprobe_predefined.conf'
        if group_os_family == 'multiple':
            dump_filename = f'modprobe_predefined_{node.get_node_name()}.conf'

        utils.dump_file(cluster, config, dump_filename)
        node.put(io.StringIO(config), predefined_file_path, backup=True, sudo=True)
        node.sudo("modprobe -a %s" % raw_config)

    defer.flush()

    return True


def is_modprobe_valid(group: NodeGroup) -> Tuple[bool, bool, RunnersGroupResult]:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log
    defer = group.new_defer()

    lsmod_collector = CollectorCallback(cluster)
    config_collector = CollectorCallback(cluster)
    defer.sudo("lsmod", warn=True, callback=lsmod_collector)
    defer.sudo(f"cat {predefined_file_path}", warn=True, callback=config_collector)
    defer.flush()

    is_valid = True
    is_config_valid = True

    for node in defer.get_ordered_members_list():
        expected_config = generate_config(node)
        if not expected_config:
            continue

        expected_modules = expected_config.rstrip('\n').split('\n')

        host = node.get_host()
        lsmod_result = lsmod_collector.result[host]
        actual_config = config_collector.result[host]

        for module_name in expected_modules:
            if module_name not in lsmod_result.stdout:
                logger.debug(f'Kernel module {module_name} is not found at {host}')
                is_valid = False

        if expected_config != actual_config.stdout:
            logger.debug(f'Config is outdated at {host}')
            is_config_valid = False

    return is_valid, is_config_valid, lsmod_collector.result
