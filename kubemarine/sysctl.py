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

"""
This module works with sysctl on remote systems.
Using this module you can generate new sysctl configs, install and apply them.
"""

import io
from typing import Dict, Union, Optional, List, cast

from kubemarine.core import utils, inventory
from kubemarine.core.cluster import KubernetesCluster, enrichment, EnrichmentStage
from kubemarine.core.group import NodeGroup, RunnersGroupResult, AbstractGroup, RunResult
from kubemarine.core.yaml_merger import default_merger

ERROR_PID_MAX_NOT_SET = "The 'kernel.pid_max' value is not set for node {node!r}"
ERROR_PID_MAX_EXCEEDS = ("The 'kernel.pid_max' value = {value!r} for node {node!r} "
                         "is greater than the maximum allowable {max!r}")
ERROR_PID_MAX_REQUIRED = ("The 'kernel.pid_max' value = {value!r} for node {node!r} "
                          "is lower than the minimum required for kubelet configuration = {required!r}")
WARN_PID_MAX_LOWER_DEFAULT = ("The 'kernel.pid_max' value = {value!r} for node {node!r} "
                              "is lower than default system value = {default!r}")


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    # Set global default 'kernel.pid_max', and create inventory patches
    _apply_default_pid_max(cluster)

    # Strip obsolete blank values, and strtoint()
    # This should only affect formatting, but not further enrichment.
    _format_inventory(cluster.inventory, [])
    for i, patch in enumerate(cluster.inventory['patches']):
        _format_inventory(patch, ['patches', i])

    # Fill KubernetesCluster.nodes_inventory with sysctl settings
    inventory.patch_inventory(cluster, ['services', 'sysctl'])

    # Convert settings for each node and apply defaults
    _convert_inventory(cluster)
    _apply_common_defaults(cluster)

    # Other verifications
    _verify_pid_max(cluster)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['reconfigure'])
def enrich_reconfigure_inventory(cluster: KubernetesCluster) -> None:
    sysctl_config = utils.subdict_yaml(
        cluster.procedure_inventory.get('services', {}), ['sysctl'])

    if sysctl_config:
        default_merger.merge(cluster.inventory.setdefault('services', {}), utils.deepcopy_yaml(sysctl_config))


def _format_inventory(config: dict, path: List[Union[str, int]]) -> None:
    sysctl_config: Dict[str, Union[str, int, dict]] = config.get('services', {}).get('sysctl', {})
    path = path + ['services', 'sysctl']

    for key in sysctl_config:
        _format_value(sysctl_config, key, path)


def _format_value(sysctl_config: Dict[str, Union[str, int, dict]], key: str, path: List[Union[str, int]]) -> None:
    value = sysctl_config[key]
    if isinstance(value, str):
        # Obsolete approach to render values.
        value = value.strip()
        if value == '':
            sysctl_config[key] = value
        else:
            sysctl_config[key] = _strtoint(value, path + [key])


def _convert_inventory(cluster: KubernetesCluster) -> None:
    for node in cluster.nodes['all'].get_ordered_members_list():
        host = node.get_host()
        sysctl_config: Dict[str, Union[str, int, dict]] = cluster.nodes_inventory[host]['services']['sysctl']

        for key in sysctl_config:
            _convert_value(sysctl_config, key)


def _convert_value(sysctl_config: Dict[str, Union[str, int, dict]], key: str) -> None:
    value = sysctl_config[key]
    install: Optional[bool] = None
    if isinstance(value, str):  # value == ''
        value = 0
        install = False

    if isinstance(value, int):
        sysctl_config[key] = value = {
            'value': value,
        }

    if install is not None:
        value['install'] = install


def _strtoint(value: str, path: List[Union[str, int]]) -> int:
    try:
        return utils.strtoint(value)
    except ValueError as e:
        raise ValueError(f"{str(e)} in section {utils.pretty_path(path)}") from None


def _apply_common_defaults(cluster: KubernetesCluster) -> None:
    for node in cluster.nodes['all'].get_ordered_members_list():
        host = node.get_host()
        sysctl_config: Dict[str, dict] = cluster.nodes_inventory[host]['services']['sysctl']

        for key, value in sysctl_config.items():
            if value.get('groups') is None and value.get('nodes') is None:
                value['groups'] = ['control-plane', 'worker', 'balancer']

            value.setdefault('install', True)

            if value.get('nodes') is not None:
                all_nodes_names = cluster.nodes['all'].get_nodes_names()
                unknown_nodes = set(value['nodes']) - set(all_nodes_names)
                if unknown_nodes:
                    # Only warn instead of raising an error to allow remove & add the same node.
                    cluster.log.warning(
                        f"Unknown node names {', '.join(map(repr, unknown_nodes))} "
                        f"provided for kernel parameter {key!r}. ")


def _apply_default_pid_max(cluster: KubernetesCluster) -> None:
    inventory_ = cluster.inventory

    global_pid_max = inventory_['services']['sysctl']['kernel.pid_max']
    if not isinstance(global_pid_max, dict) or 'value' in global_pid_max:
        # If custom value is provided, it should be spread across the specified nodes only
        # unless explicitly overridden in the patches
        return

    global_pid_max.setdefault('value', _get_pid_max(cluster))

    # If kubelet config for some node has different maxPods or podPidsLimit,
    # calculate kernel.pid_max for this node and register it in the default patch.
    nodes_different_value: Dict[int, List[str]] = {}
    for node in cluster.make_group_from_roles(['control-plane', 'worker']).get_ordered_members_list():
        node_pid_max = _get_pid_max(cluster, node)
        if node_pid_max != global_pid_max['value']:
            nodes_different_value.setdefault(node_pid_max, []).append(node.get_node_name())

    for pid_max, nodes in nodes_different_value.items():
        inventory_patch = {
            'nodes': nodes,
            'services': {'sysctl': {
                'kernel.pid_max': pid_max
            }}
        }
        inventory_['patches'].insert(0, inventory_patch)


def _verify_pid_max(cluster: KubernetesCluster) -> None:
    for node in cluster.make_group_from_roles(['control-plane', 'worker']).get_ordered_members_list():
        node_name = node.get_node_name()

        value = get_parameter(cluster, node, 'kernel.pid_max')
        required_pid_max = _get_pid_max(cluster, node)

        if value is None:
            raise Exception(ERROR_PID_MAX_NOT_SET.format(node=node_name))
        if value > 2 ** 22:
            raise Exception(ERROR_PID_MAX_EXCEEDS.format(node=node_name, value=value, max=2 ** 22))
        if value < required_pid_max:
            raise Exception(ERROR_PID_MAX_REQUIRED.format(node=node_name, value=value, required=required_pid_max))
        if value < 32768:
            cluster.log.warning(WARN_PID_MAX_LOWER_DEFAULT.format(node=node_name, value=value, default=32768))


def get_parameter(cluster: KubernetesCluster, node: AbstractGroup[RunResult], key: str) -> Optional[int]:
    host = node.get_host()
    config = cluster.nodes_inventory[host]['services']['sysctl'].get(key, {})

    group = cluster.create_group_from_groups_nodes_names(
        config.get('groups', []), config.get('nodes', []))

    if not config.get('install', False) or not group.has_node(node.get_node_name()):
        return None

    value: int = config['value']
    return value


def make_config(cluster: KubernetesCluster, node: AbstractGroup[RunResult]) -> str:
    """
    Converts parameters from inventory['services']['sysctl'] to a string in the format of sysctl.conf.
    """
    host = node.get_host()
    config = ""
    for key in cluster.nodes_inventory[host]['services']['sysctl']:
        value = get_parameter(cluster, node, key)
        if value is not None:
            config += "%s = %s\n" % (key, value)

    return config


def configure(group: NodeGroup) -> RunnersGroupResult:
    """
    Generates and uploads sysctl configuration to the group.
    The configuration will be placed in sysctl daemon directory.
    """
    cluster: KubernetesCluster = group.cluster
    defer = group.new_defer()

    for node in defer.get_ordered_members_list():
        config = make_config(cluster, node)
        node.sudo('rm -f /etc/sysctl.d/98-*-sysctl.conf')
        utils.dump_file(cluster, config, f'sysctl/98-kubemarine-sysctl_{node.get_node_name()}.conf')
        node.put(io.StringIO(config), '/etc/sysctl.d/98-kubemarine-sysctl.conf', backup=True, sudo=True)

    defer.flush()

    return group.sudo('ls -la /etc/sysctl.d/98-kubemarine-sysctl.conf')


def is_valid(group: NodeGroup) -> bool:
    logger = group.cluster.log

    verify_results = group.sudo('sysctl -a')

    sysctl_valid = True
    for node in group.get_ordered_members_list():
        host = node.get_host()
        result = verify_results[host]
        config = make_config(group.cluster, node)
        for parameter in config.rstrip('\n').split('\n'):
            if parameter not in result.stdout:
                logger.debug(f'Kernel parameter {parameter!r} is not found at {host}')
                sysctl_valid = False

    return sysctl_valid


def reload(group: NodeGroup) -> RunnersGroupResult:
    """
    Reloads sysctl configuration in the specified group.
    """
    return group.sudo('sysctl --system')


def setup_sysctl(group: NodeGroup) -> bool:
    cluster: KubernetesCluster = group.cluster

    if is_valid(group):
        cluster.log.debug("Skipped - all necessary kernel parameters are presented")
        return False

    group.call_batch([
        configure,
        reload,
    ])

    return True


def _get_pid_max(cluster: KubernetesCluster, node: NodeGroup = None) -> int:
    from kubemarine.kubernetes import components  # pylint: disable=cyclic-import

    kubeadm_kubelet = cluster.inventory["services"]["kubeadm_kubelet"]
    max_pods: int = kubeadm_kubelet.get("maxPods", 110)
    pod_pids_limit: int = kubeadm_kubelet.get("podPidsLimit", 4096)

    if node is not None:
        flags = components.get_patched_flags_for_section(cluster, 'kubelet', node)
        if 'maxPods' in flags:
            max_pods = cast(int, flags['maxPods'])
        if 'podPidsLimit' in flags:
            pod_pids_limit = cast(int, flags['podPidsLimit'])

    return max_pods * pod_pids_limit + 2048
