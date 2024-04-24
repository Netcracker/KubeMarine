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
from kubemarine.packages import disable_unattended_upgrade


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Disable unattended upgrade for important packages")

    def run(self, res: DynamicResources) -> None:
        group = res.cluster().make_group_from_roles(['all'])
        group.call(disable_unattended_upgrade)


class DisableUnattendedUpgrades(RegularPatch):
    def __init__(self) -> None:
        super().__init__("disable_unattended_upgrades")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Disable unattended upgrades on debian nodes for important packages.
            """.rstrip()
        )