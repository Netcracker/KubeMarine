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
from kubemarine.thirdparties import install_thirdparty

class TheAction(Action):
    def __init__(self):
        super().__init__("Reinstall /usr/bin/etcdctl thirdparty")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        thirdparty = '/usr/bin/etcdctl'
        install_thirdparty(cluster.nodes['all'], thirdparty)


class EtcdctlThirdparty(RegularPatch):
    def __init__(self):
        super().__init__("etcdctl_thirdparty")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reinstall /usr/bin/etcdctl thirdparty to use ctr tool inside
            """.rstrip()
        )
