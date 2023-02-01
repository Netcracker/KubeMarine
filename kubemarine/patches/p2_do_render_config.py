# Copyright 2021-2022 NetCracker Technology Corporation
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

import ruamel.yaml

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self):
        super().__init__("Migrate template to config plugin procedure type")

    def run(self, res: DynamicResources):
        inventory = res.formatted_inventory()
        for plugin, plugin_item in inventory.get('plugins', {}).items():
            for i, step in enumerate(plugin_item.get('installation', {}).get('procedures', [])):
                apply_types = list(step)
                for si, apply_type in enumerate(apply_types):
                    if apply_type == 'template' and 'do_render' in step[apply_type]:
                        res.logger().info(f"Changing procedure type from 'template' to 'config' "
                                          f"for plugin {plugin!r} at installation step {i}.")
                        configs = step.pop(apply_type)
                        step: ruamel.yaml.CommentedMap = step
                        step.insert(si, 'config', configs)
                        self.recreate_inventory = True

        if not self.recreate_inventory:
            res.logger().info("Nothing has changed")


class DoRenderConfig(Patch):
    def __init__(self):
        super().__init__("do_render_config")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            KubeMarine declares that do_render parameter can be specified only for config procedure type of plugins.
            But technically it was possible to specify the parameter for template procedure type as well.
            The patch automatically changes template to config procedure type in the inventory where necessary. 
            """.rstrip()
        )
