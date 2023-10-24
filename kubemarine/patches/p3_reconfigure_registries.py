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
from kubemarine.cri.containerd import contains_old_format_properties, configure_containerd, configure_ctr_flags


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reconfigure registries containerd configuration")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        cluster = res.cluster()
        if cluster.inventory['services']['cri']['containerRuntime'] == 'docker':
            logger.info("Docker cri is used, updating containerd configuration is not needed")
            return

        prev_cluster = res.create_deviated_cluster({
            'p3_reconfigure_registries': False
        })

        if 'containerdRegistriesConfig' not in cluster.inventory['services']['cri'] or \
                'containerdRegistriesConfig' in prev_cluster.inventory['services']['cri']:
            logger.info("Nothing changed, updating containerd configuration is not needed")
            return
        node_group = cluster.make_group_from_roles(['control-plane', 'worker'])
        node_group.call(configure_ctr_flags)
        node_group.call(configure_containerd)


class ReconfigureRegistries(RegularPatch):
    def __init__(self) -> None:
        super().__init__("reconfigure_registries")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch reconfigure containerd registries configuration and migrate it to new format.
            """.rstrip()
        )
