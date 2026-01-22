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
from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources

PATCH_ID = "pin_kubernetes_version_default"
PREVIOUS_DEFAULT_KUBERNETES_VERSION = "v1.33.0"


class PinKubernetesVersionDefaultAction(Action):
    def __init__(self) -> None:
        super().__init__(PATCH_ID)

    def run(self, res: DynamicResources) -> None:
        inventory = res.inventory()

        services = inventory.get("services")
        if services is None:
            services = {}
            inventory["services"] = services
        elif not isinstance(services, dict):
            res.logger().info(
                "Patch %r skipped: inventory 'services' section is not a mapping.", PATCH_ID
            )
            return

        kubeadm = services.get("kubeadm")
        if kubeadm is None:
            kubeadm = {}
            services["kubeadm"] = kubeadm
        elif not isinstance(kubeadm, dict):
            res.logger().info(
                "Patch %r skipped: inventory 'services.kubeadm' section is not a mapping.", PATCH_ID
            )
            return

        if "kubernetesVersion" in kubeadm and kubeadm["kubernetesVersion"] is not None:
            res.logger().info(
                "Patch %r skipped: 'services.kubeadm.kubernetesVersion' is already specified.", PATCH_ID
            )
            return

        kubeadm["kubernetesVersion"] = PREVIOUS_DEFAULT_KUBERNETES_VERSION
        self.recreate_inventory = True
        res.logger().info(
            "Pinned 'services.kubeadm.kubernetesVersion' to %s to preserve the previous default.",
            PREVIOUS_DEFAULT_KUBERNETES_VERSION,
        )


class PinKubernetesVersionDefaultPatch(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__(PATCH_ID)

    @property
    def action(self) -> Action:
        return PinKubernetesVersionDefaultAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Set services.kubeadm.kubernetesVersion to {PREVIOUS_DEFAULT_KUBERNETES_VERSION} if it is not specified
            in the inventory, to preserve the previous default after the default was updated.
            """.rstrip()
        )
