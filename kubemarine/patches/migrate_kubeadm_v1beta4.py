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

from textwrap import dedent
from typing import Optional

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources

EXTRA_ARGS_SECTIONS = (('apiServer',), ('scheduler',), ('controllerManager',), ('etcd', 'local'))


def migrate_inventory(inventory: dict) -> bool:
    """
    Convert v1beta3 overrides in `services.kubeadm` to v1beta4.
    Only explicitly specified sections are changed, defaults are not expanded.

    :return: True if the inventory is changed.
    """
    services: dict = inventory.get('services', {})
    kubeadm: Optional[dict] = services.get('kubeadm')
    if kubeadm is None:
        return False

    changed = False
    if kubeadm.get('apiVersion') == 'kubeadm.k8s.io/v1beta3':
        kubeadm['apiVersion'] = 'kubeadm.k8s.io/v1beta4'
        changed = True

    for path in EXTRA_ARGS_SECTIONS:
        section = kubeadm
        for key in path:
            section = section.get(key) or {}
        extra_args = section.get('extraArgs')
        if isinstance(extra_args, dict):
            section['extraArgs'] = [{'name': name, 'value': value} for name, value in extra_args.items()]
            changed = True

    api_server = kubeadm.get('apiServer') or {}
    if 'timeoutForControlPlane' in api_server:
        timeout = api_server['timeoutForControlPlane']
        timeouts = services.get('kubeadm_timeouts') or {}
        if timeouts.get('controlPlaneComponentHealthCheck', timeout) != timeout:
            raise ValueError("Conflicting services.kubeadm.apiServer.timeoutForControlPlane "
                             "and services.kubeadm_timeouts.controlPlaneComponentHealthCheck")
        del api_server['timeoutForControlPlane']
        services.setdefault('kubeadm_timeouts', {})['controlPlaneComponentHealthCheck'] = timeout
        changed = True

    return changed


class KubeadmV1Beta4Action(Action):
    def __init__(self) -> None:
        super().__init__('migrate_kubeadm_v1beta4')

    def run(self, res: DynamicResources) -> None:
        if migrate_inventory(res.inventory()):
            self.recreate_inventory = True
            res.logger().info("services.kubeadm is migrated to kubeadm.k8s.io/v1beta4")
        else:
            res.logger().info("services.kubeadm already uses kubeadm.k8s.io/v1beta4 format")


class KubeadmV1Beta4Patch(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__('migrate_kubeadm_v1beta4')

    @property
    def action(self) -> Action:
        return KubeadmV1Beta4Action()

    @property
    def description(self) -> str:
        return dedent(
            """\
            Migrate services.kubeadm in the inventory to kubeadm.k8s.io/v1beta4:
            apiVersion v1beta3 is changed to v1beta4, extraArgs maps are converted to lists of {name, value},
            and apiServer.timeoutForControlPlane is moved to services.kubeadm_timeouts.controlPlaneComponentHealthCheck.
            The kube-system/kubeadm-config ConfigMap is not changed, kubeadm already stores it as v1beta4.
            Custom Jinja templates that read extraArgs as a map should be updated manually.
            """.rstrip()
        )
