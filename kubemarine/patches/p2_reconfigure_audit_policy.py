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

from kubemarine.core import yaml_merger
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reconfigure Kubernetes audit policy")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        raw_cluster_policy = res.raw_inventory().get('services', {}).get('audit', {}).get('cluster_policy', {})

        if 'rules' not in raw_cluster_policy or yaml_merger.is_list_extends(raw_cluster_policy['rules']):
            install.run_tasks(res, ['deploy.kubernetes.audit'])
        else:
            return logger.info("Audit policy is redefined in the inventory file. Nothing to change.")


class ReconfigureAuditPolicy(RegularPatch):
    def __init__(self) -> None:
        super().__init__("reconfigure_audit_policy")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Disable logging of Kubernetes audit events for the Calico API server's checking API access.
            
            If the Calico plugin or its API server are disabled, the policy is still reconfigured,
            but new rules do not affect anything and are only reserved for possible future extensions.
            
            The patch is equivalent to `kubemarine install --tasks deploy.kubernetes.audit`.
            """.rstrip()
        )
