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
from typing import Tuple, List, Union, Optional

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback, AbstractGroup, RunResult

predefined_file_path = "/etc/modules-load.d/predefined.conf"

ERROR_BLANK_MODULE = "Found blank kernel module at path {path}"
ERROR_DUPLICATE_MODULE = "Kernel module {module_name!r} is duplicated in the inventory"


@enrichment(EnrichmentStage.FULL)
def enrich_kernel_modules(cluster: KubernetesCluster) -> None:
    """
    The method enrich the list of kernel modules ('services.modprobe') according to OS family
    """

    for os_family in ('debian', 'rhel', 'rhel8', 'rhel9'):
        # Remove the section for OS families if no node has these OS families.
        modprobe_config = cluster.inventory["services"]["modprobe"]
        if cluster.nodes['all'].get_subgroup_with_os(os_family).is_empty():
            del modprobe_config[os_family]
            continue

        modprobe_config[os_family] = modules_list = _convert_modprobe_config(cluster, os_family)

        _verify_modules_list(modules_list)
        _apply_defaults(cluster, modules_list)


def _convert_modprobe_config(cluster: KubernetesCluster, os_family: str) -> List[dict]:
    modprobe_config: List[Union[str, dict]] = cluster.inventory["services"]["modprobe"][os_family]

    modules_list: List[dict] = []
    for i, module_name in enumerate(modprobe_config):
        config = _convert_module(module_name, ["services", "modprobe", os_family, i])
        if config is not None:
            modules_list.append(config)

    return modules_list


def _convert_module(module_name: Union[str, dict], path: List[Union[str, int]]) -> Optional[dict]:
    if isinstance(module_name, str):
        # Obsolete approach to render values. Empty modules should be removed from the list.
        module_name = module_name.strip()
        if module_name == '':
            return None

        config = {
            'modulename': module_name,
        }
    else:
        config = module_name

    config['modulename'] = config['modulename'].strip()
    if config['modulename'] == '':
        raise Exception(ERROR_BLANK_MODULE.format(path=utils.pretty_path(path + ['modulename'])))

    return config


def _verify_modules_list(modules_list: List[dict]) -> None:
    known_modules = set()
    for config in modules_list:
        module_name = config['modulename']
        if module_name in known_modules:
            raise Exception(ERROR_DUPLICATE_MODULE.format(module_name=module_name))

        known_modules.add(module_name)


def _apply_defaults(cluster: KubernetesCluster, modules_list: List[dict]) -> None:
    for config in modules_list:
        if config.get('groups') is None and config.get('nodes') is None:
            config['groups'] = ['control-plane', 'worker', 'balancer']

        config.setdefault('install', True)

        if config.get('nodes') is not None:
            all_nodes_names = cluster.nodes['all'].get_nodes_names()
            unknown_nodes = set(config['nodes']) - set(all_nodes_names)
            if unknown_nodes:
                # Only warn instead of raising an error to allow remove & add the same node.
                cluster.log.warning(
                    f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                    f"provided for kernel module {config['modulename']!r}. ")


def generate_config(node: AbstractGroup[RunResult]) -> str:
    cluster: KubernetesCluster = node.cluster
    config = ''
    modprobe_config: List[dict] = cluster.inventory['services']['modprobe'][node.get_nodes_os()]
    for module_config in modprobe_config:
        group = cluster.create_group_from_groups_nodes_names(
            module_config.get('groups', []), module_config.get('nodes', []))

        if not module_config['install'] or not group.has_node(node.get_node_name()):
            continue

        config += module_config['modulename'] + "\n"

    return config


def setup_modprobe(group: NodeGroup) -> bool:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log

    is_valid, is_config_valid, result = is_modprobe_valid(group)

    if is_valid and is_config_valid:
        logger.debug("Skipped - all necessary kernel modules are presented")
        logger.debug(result)
        return False

    defer = group.new_defer()
    for node in defer.get_ordered_members_list():
        config = generate_config(node)
        if not config:
            continue
        raw_config = config.replace('\n', ' ')

        logger.debug("Uploading config...")
        dump_filename = f'modprobe/modprobe_predefined_{node.get_node_name()}.conf'

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
        actual_modules = {mod.split()[0]
                          for mod in lsmod_result.stdout.rstrip('\n').split('\n')[1:]}

        actual_config = config_collector.result[host]

        for module_name in expected_modules:
            if module_name not in actual_modules:
                logger.debug(f'Kernel module {module_name} is not found at {host}')
                is_valid = False

        if expected_config != actual_config.stdout:
            logger.debug(f'Config is outdated at {host}')
            is_config_valid = False

    return is_valid, is_config_valid, lsmod_collector.result
