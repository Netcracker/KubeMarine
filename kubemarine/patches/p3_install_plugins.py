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
        super().__init__("install plugins")

    def run(self, res: DynamicResources):
        # task 'deploy.plugins' of 'install' procedure.
        install.deploy_plugins(res.cluster())

        # alternative, more boiler-plate way, but can take cumulative points into account
        # In this case it is completely not necessary,
        # because cumulative points currently do not work with 'deploy.plugins' task.
        try:
            # patch engine knows nothing about tasks, so need to add tasks-related execution arguments
            # See flow.new_tasks_flow_parser()
            res.context['execution_arguments']['tasks'] = 'deploy.plugins'
            res.context['execution_arguments']['exclude'] = ''
            flow.run_tasks(res, install.tasks, cumulative_points=install.cumulative_points)
        finally:
            del res.context['execution_arguments']['tasks']
            del res.context['execution_arguments']['exclude']


class InstallPlugins(Patch):
    def __init__(self):
        super().__init__("install_plugins")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return 'Equivalent to kubemarine install --tasks="deploy.plugins"'
