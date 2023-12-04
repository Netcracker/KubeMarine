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
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set previous default Kubernetes version")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        inventory = res.formatted_inventory()
        if 'kubernetesVersion' not in inventory.get('services', {}).get('kubeadm', {}):
            logger.debug("Set services.kubeadm.kubernetesVersion = v1.26.7 in the inventory")
            inventory.setdefault('services', {}).setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.26.7'
            self.recreate_inventory = True
        else:
            logger.info("Skipping the patch as services.kubeadm.kubernetesVersion is explicitly provided.")


class PinKubernetesVersion(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("pin_kubernetes_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            The patch sets previous default Kubernetes version in the inventory if the version was not explicitly specified.
            """.rstrip()
        )
