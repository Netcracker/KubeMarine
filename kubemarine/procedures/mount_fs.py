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

from collections import OrderedDict
from typing import List, Any

from kubemarine import fsmount, kubernetes, system
from kubemarine.core import flow
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.procedures import install


def mount_filesystems(cluster: KubernetesCluster) -> None:
    # procedure_inventory is the raw fsmount list from procedure.yaml
    fsmount_list: List[dict] = cluster.procedure_inventory  # type: ignore[assignment]

    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    timeout_config = cluster.inventory['globals']['expect']['pods']['kubernetes']

    for node in cluster.nodes['all'].get_ordered_members_list():
        node_name = node.get_node_name()
        node_config = node.get_config()
        is_k8s_node = 'control-plane' in node_config['roles'] or 'worker' in node_config['roles']

        applicable = fsmount.get_applicable_items(cluster, node, fsmount_list)
        if not applicable:
            continue

        if is_k8s_node:
            cluster.log.debug(f"Draining node {node_name!r} before fsmount setup")
            first_control_plane.sudo(
                kubernetes.prepare_drain_command(cluster, node_name, disable_eviction=False),
                warn=True, pty=True)

        for item in applicable:
            mount_path = item['path'].rstrip('/')
            cluster.log.debug(f"Removing files in {mount_path!r} on {node_name!r}")
            node.sudo(f"rm -rf {mount_path}/*")

        node.call(fsmount.setup_fsmount, fsmount_list=fsmount_list)

        cluster.log.debug(f"Rebooting node {node_name!r} after fsmount setup")
        system.perform_group_reboot(node)

        if is_k8s_node:
            cluster.log.debug(f"Uncordoning node {node_name!r} after reboot")
            first_control_plane.wait_command_successful(
                f"kubectl uncordon {node_name}",
                hide=False, pty=True,
                timeout=timeout_config['timeout'],
                retries=timeout_config['retries'])


tasks = OrderedDict({
    "mount_filesystems": mount_filesystems,
    "overview": install.overview,
})


class MountFsAction(flow.TasksAction):
    def __init__(self) -> None:
        super().__init__('mount_fs', tasks, recreate_inventory=True)


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for mounting filesystems defined in procedure.yaml.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='mount_fs')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([MountFsAction()]).run_flow(context)


if __name__ == '__main__':
    main()
