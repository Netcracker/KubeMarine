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

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes, cri, system
from kubemarine.cri import containerd


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Manage containerd sandbox_image and --pod-infra-container-image flag of kubelet")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        cri_impl = cri.get_initial_cri_impl(res.raw_inventory())
        if cri_impl != 'containerd':
            logger.info(f"Patch is not actual for {cri_impl!r} CRI")
            return

        cluster = res.cluster()
        expected_sandbox_image = containerd.get_sandbox_image(cluster.inventory['services']['cri'])
        cluster_changed = False
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])

        containerd_configs = containerd.fetch_containerd_config(kubernetes_nodes)
        if any(config['plugins']['io.containerd.grpc.v1.cri'].get('sandbox_image') != expected_sandbox_image
               for config in containerd_configs.values()):
            containerd.configure_containerd(kubernetes_nodes)
            cluster_changed = True

        if kubernetes.fix_flag_kubelet(kubernetes_nodes):
            logger.debug(f"Restarting kubelet on all Kubernetes nodes")
            system.restart_service(kubernetes_nodes, 'kubelet')
            cluster_changed = True

        if not cluster_changed:
            logger.info(f"Patch is not actual for the cluster")


class ManagedSandboxImage(RegularPatch):
    def __init__(self) -> None:
        super().__init__("manage_containerd_sandbox_image")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Make
            - sandbox_image of containerd configuration, and
            - --pod-infra-container-image flag of kubelet
            the same and fully controlled by Kubemarine.
            """.rstrip()
        )
