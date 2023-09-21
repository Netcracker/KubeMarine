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
        super().__init__("Override target ports")

    def run(self, res: DynamicResources) -> None:
        inventory = res.formatted_inventory()
        self.recreate_inventory = True
        target_ports = inventory.setdefault("services", {})\
            .setdefault("loadbalancer", {})\
            .setdefault("target_ports", {})
        target_ports.setdefault("http", 80)
        target_ports.setdefault("https", 443)


class OverrideTargetPorts(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("override_target_ports")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch overrides target ports (services.loadbalancer.target_ports) for existed clusters 
            because of new defaults
            """.rstrip()
        )
