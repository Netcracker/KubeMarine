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

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine import plugins

class TheAction(Action):
    def __init__(self):
        super().__init__("Enable Calico metrics")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        calico_plugin = cluster.inventory['plugins']['calico']
        if not calico_plugin.get('install', False) \
                or calico_plugin.get('installation', {}).get('procedures') is None:
            cluster.log.info("calico plugin is disabled or its procedures aren't defined")
            return

        cluster.log.info(f"Сalico metrics will be configured on nodes")
        plugins.install_plugin(cluster, 'calico', calico_plugin['installation']['procedures'])


class EnableMetrics(Patch):
    def __init__(self):
        super().__init__("enable_calico_metrics")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Enable calico metrics.
            """.rstrip()
        )