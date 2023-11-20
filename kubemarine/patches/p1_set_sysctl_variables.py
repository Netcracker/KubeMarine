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
from kubemarine import sysctl

class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set sysctl variables")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        node_group = cluster.make_group_from_roles(['all'])

        # add nf_conntrack module to predefined modules list
        # and load it without the node reboot
        for node in node_group:
            node.sudo("echo nf_conntrack >> /etc/modules-load.d/predefined.conf ; modprobe -a nf_conntrack")

        # configure syslog variables
        node_group.call(sysctl.configure)
        node_group.call(sysctl.reload)
        

class SetSysctlVariables(RegularPatch):
    def __init__(self) -> None:
        super().__init__("set_sysctl_variables")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch sets kernel variables with sysctl at all the nodes according to the new defaults.
            """.rstrip()
        )
