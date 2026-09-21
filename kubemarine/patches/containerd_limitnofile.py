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
from kubemarine.procedures import install

class ContainerdLimitNOFILEAction(Action):
    def run(self, res: DynamicResources) -> None:
        install.run_tasks(res, ['prepare.cri.configure'])

class ContainerdLimitNOFILEPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__("containerd_limitnofile")

    @property
    def action(self) -> Action:
        return ContainerdLimitNOFILEAction("containerd_limitnofile")

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch uploads containerd drop-in on all nodes 
            to configure containerd LimitNOFILE soft/hard limits.
            """.rstrip()
        )