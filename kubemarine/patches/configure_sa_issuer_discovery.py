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
from kubemarine import kubernetes_accounts


class ConfigureSAIssuerDiscoveryAction(Action):
    def __init__(self) -> None:
        super().__init__("Configure SA Issuer Discovery")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        kubernetes_accounts.handle_authenticated_sa_issuer_discovery(cluster)


class ConfigureSAIssuerDiscovery(RegularPatch):
    def __init__(self) -> None:
        super().__init__("configure_sa_issuer_discovery")

    @property
    def action(self) -> Action:
        return ConfigureSAIssuerDiscoveryAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch applies new default parameter rbac.authenticated-issuer-discovery.
            By default, it will allow unauthenticated access to service account issuer discovery endpoint.
            """.rstrip()
        )