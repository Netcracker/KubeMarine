# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self):
        super().__init__("run whoami")

    def run(self, res: DynamicResources):
        whoami = res.cluster().nodes['all'].sudo("whoami")
        res.logger().info(whoami)


class RunWhoami(Patch):
    def __init__(self):
        super().__init__("run_whoami")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return 'Run whoami'
