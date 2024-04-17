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
        super().__init__("Move globals.nodes.boot.timeout to per-node configuration")

    def run(self, res: DynamicResources) -> None:
        inventory = res.inventory()

        if 'boot' in inventory.get('globals', {}).get('nodes', {}):
            self.recreate_inventory = True
            inventory.setdefault('node_defaults', {})['boot'] = inventory['globals']['nodes'].pop('boot')
        else:
            res.logger().info("Nothing has changed")


class TimeoutPerNode(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("boot_timeout_per_node")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Move globals.nodes.boot.timeout to node_defaults.boot.timeout
            """.rstrip()
        )
