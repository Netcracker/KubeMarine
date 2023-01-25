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

from kubemarine.core import static
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self):
        super().__init__("Turn mandatory packages off for backward compatibility", recreate_inventory=True)

    def run(self, res: DynamicResources):
        for package in static.DEFAULTS["services"]["packages"]['mandatory'].keys():
            res.formatted_inventory().setdefault('services', {}).setdefault('packages', {})\
                .setdefault('mandatory', {})[package] = False


class MandatoryPackagesOff(Patch):
    def __init__(self):
        super().__init__("mandatory_packages_off")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            New KubeMarine automatically installs and manages all mandatory packages.
            Old users had to specify them inside services.packages.install section.
            For backward compatibility KubeMarine should not manage mandatory packages for old clusters.
            The patch turns off the management in the inventory.
            """.rstrip()
        )
