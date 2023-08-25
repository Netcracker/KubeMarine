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
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reconfigure Kubernetes audit policy")

    def run(self, res: DynamicResources) -> None:
        install.run_tasks(res, ['deploy.kubernetes.audit'])


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
            Reconfigure Kubernetes audit policy.
            To find new default target configuration, refer to kubemarine/resources/configurations/defaults.yaml
            - services.kubeadm.apiServer.extraArgs.audit-*
            - services.audit.cluster_policy
            The patch is equivalent to `kubemarine install --tasks deploy.kubernetes.audit`.
            """.rstrip()
        )
