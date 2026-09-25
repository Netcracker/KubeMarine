# Copyright 2026 NetCracker Technology Corporation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes import components


class MigrationAction(Action):
    def __init__(self) -> None:
        super().__init__('Migrate kubeadm configuration to v1beta4')

    def run(self, res: DynamicResources) -> None:
        inventory_changed = components.migrate_inventory(res.inventory())
        components.migrate_kubeadm_configmap(res.cluster())

        # Persist the inventory only after the in-cluster migration succeeds.
        self.recreate_inventory = inventory_changed


class KubeadmV1Beta4Patch(RegularPatch):
    def __init__(self) -> None:
        super().__init__('migrate_kubeadm_v1beta4')

    @property
    def action(self) -> Action:
        return MigrationAction()

    @property
    def description(self) -> str:
        return ('Convert the inventory and kube-system/kubeadm-config to v1beta4 before a Kubernetes upgrade. '
                'Inventory extraArgs are converted to named-argument lists and timeoutForControlPlane is moved '
                'to services.kubeadm_timeouts. The ConfigMap is migrated and validated using the installed '
                'kubeadm while preserving the running Kubernetes version and custom settings. The migration '
                'procedure backs up a changed inventory, and the original ConfigMap is saved in the dump '
                'directory before it is updated. No components are restarted.')
