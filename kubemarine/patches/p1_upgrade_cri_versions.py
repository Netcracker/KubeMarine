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
        super().__init__("Upgrade cri versions")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        if cluster.inventory['services']['cri']['containerRuntime'] == 'docker':
            res.logger().info("Skip upgrade for clusters based on docker.")
            return

        flow.run_tasks(res, install.tasks, cumulative_points=install.cumulative_points,
                       tasks_filter=['prepare.package_manager.configure', 'prepare.cri'])


class UpgradeCriVersions(Patch):
    def __init__(self):
        super().__init__("upgrade_cri_versions")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Upgrade cri versions for clusters based on containerd.
Note that you may probably need to update services.packages.package_manager.repositories section preliminarily.
Equivalent to 'kubemarine install --tasks=prepare.package_manager.configure,prepare.cri' for that clusters."""
