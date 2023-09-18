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
        super().__init__("Mark proxy protocol disabled for minHA cluster")

    def run(self, res: DynamicResources) -> None:
        inventory = res.formatted_inventory()
        log = res.logger()
        if any('balancer' in node['roles'] for node in inventory['nodes']) and \
                all(len(node['roles']) == 1 for node in inventory['nodes'] if 'balancer' in node['roles']):
            log.debug("Cluster contains only separate balancers. Skip marking proxy-protocol disabled")
            return

        self.recreate_inventory = True
        inventory.setdefault("plugins", {})\
            .setdefault("nginx-ingress-controller", {})\
            .setdefault("config_map", {})\
            .setdefault("use-proxy-protocol", "false")


class MarkProxyProtocolDisabled(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("mark_proxy_protocol_disabled_minha_scheme")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch marks proxy protocol disabled in cluster inventory (by default it's enabled by kubemarine),
            if cluster is in minHA scheme or doesn't have any balancers.
            """.rstrip()
        )
