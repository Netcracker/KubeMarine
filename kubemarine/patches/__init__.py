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
All files and directories inside kubemarine/patches directory should participate only in patching mechanism,
and relate to the current Kubemarine version.

The whole directory is automatically cleared and reset after new version of Kubemarine is released.
"""

from typing import List

from kubemarine import fsmount, kubernetes, system
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch, RegularPatch
from kubemarine.core.resources import DynamicResources


class _FsmountPatchAction(Action):
    def __init__(self) -> None:
        super().__init__('fsmount')

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        first_control_plane = cluster.nodes['control-plane'].get_first_member()
        timeout_config = cluster.inventory['globals']['expect']['pods']['kubernetes']

        for node in cluster.nodes['all'].get_ordered_members_list():
            node_name = node.get_node_name()
            node_config = node.get_config()
            is_k8s_node = 'control-plane' in node_config['roles'] or 'worker' in node_config['roles']

            if is_k8s_node:
                cluster.log.debug(f"Draining node {node_name!r} before fsmount setup")
                first_control_plane.sudo(
                    kubernetes.prepare_drain_command(cluster, node_name, disable_eviction=False),
                    warn=True, pty=True)

            applicable = fsmount._get_applicable_items(cluster, node)
            for item in applicable:
                mount_path = item['path'].rstrip('/')
                cluster.log.debug(f"Removing files in {mount_path!r} on {node_name!r}")
                node.sudo(f"rm -rf {mount_path}/*")

            node.call(fsmount.setup_fsmount)

            cluster.log.debug(f"Rebooting node {node_name!r} after fsmount setup")
            system.perform_group_reboot(node)

            if is_k8s_node:
                cluster.log.debug(f"Uncordoning node {node_name!r} after reboot")
                first_control_plane.wait_command_successful(
                    f"kubectl uncordon {node_name}",
                    hide=False, pty=True,
                    timeout=timeout_config['timeout'],
                    retries=timeout_config['retries'])


class _FsmountPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__('fsmount')

    @property
    def action(self) -> Action:
        return _FsmountPatchAction()

    @property
    def description(self) -> str:
        return "Sets up fsmount items (e.g. zram) with default settings on all existing cluster nodes."


patches: List[Patch] = [
    _FsmountPatch(),
]
"""
List of patches that is sorted according to the Patch.priority() before execution.
Patches that have the same priority, are executed in the declared order.
"""
