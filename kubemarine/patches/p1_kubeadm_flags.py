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

from textwrap import dedent
from io import StringIO

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes

class TheAction(Action):
    def __init__(self):
        super().__init__("Updpate kubeadm_flags after cri upgrade")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        path = 'plugins."io.containerd.grpc.v1.cri"'
        target_kubernetes_version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])
        pause_version = cluster.globals['compatibility_map']['software']['pause'][target_kubernetes_version]['version']
        sandbox = cluster.inventory["services"]["cri"]['containerdConfig'][path]["sandbox_image"]
        param_begin_pos = sandbox.rfind(":")
        sandbox = sandbox[:param_begin_pos] + ":" + str(pause_version)
        for member_node in kubernetes_nodes.get_ordered_members_list():
            kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
            kubeadm_flags = member_node.sudo(f"cat {kubeadm_flags_file}").get_simple_out()
            updated_kubeadm_flags = kubernetes._config_changer(kubeadm_flags, f"--pod-infra-container-image={sandbox}")
            member_node.put(StringIO(updated_kubeadm_flags), kubeadm_flags_file, backup=True, sudo=True)



class KubeadmFlags(RegularPatch):
    def __init__(self):
        super().__init__("kubeadm_flags")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Patch to update --pod-infra-contianer-image version after upgrading the k8s version.
            """.rstrip()
        )
