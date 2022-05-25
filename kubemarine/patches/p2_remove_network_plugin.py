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

from kubemarine import system
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import migrate_cri


class TheAction(Action):
    def __init__(self):
        super().__init__("Remove network-plugin param from kubelet")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        if cluster.inventory['services']['cri']['containerRuntime'] == 'docker':
            res.logger().info("Skip removing --network-plugin=cni as the current container runtime is docker.")
            return

        nodes = cluster.nodes['control-plane'].include_group(cluster.nodes['worker'])\
            .get_ordered_members_list(provide_node_configs=True)

        for node in nodes:
            updated = migrate_cri.patch_kubeadm_flags_unsafe(node, migrate_cri.remove_network_plugin)
            if updated:
                system.restart_service(node, 'kubelet')
                res.logger().info(f"--network-plugin=cni  is successfully removed from on node '{node['name']}'")


class RemoveNetworkPlugin(Patch):
    """See Additional steps in https://git.netcracker.com/PROD.Platform.HA/KubeMarine/-/tags/0.1.15"""

    def __init__(self):
        super().__init__("patch_network_plugin")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Remove --network-plugin=cni from /var/lib/kubelet/kubeadm-flags.env on workers and control-planes.

This patch should be used if the following conditions are satisfied:
- container runtime was migrated from docker to containerd using previous versions of kubemarine.
- you are going to upgrade to Kubernetes 1.24 or higher or already done that.
"""
