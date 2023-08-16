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
from kubemarine.cri.containerd import configure_ctr_flags


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Replace podman to ctr")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()

        if cluster.inventory["services"]["cri"]['containerRuntime'] != 'containerd':
            cluster.log.info("Used not containerd cri: migration to ctr is not needed")
            return
        cluster.log.info("Load ctr options file")
        configure_ctr_flags(cluster.make_group_from_roles(["control-plane", "worker"]))

        cluster.log.info("Update /usr/bin/etcdctl thirdparty")
        install_thirdparty(cluster.nodes['all'], '/usr/bin/etcdctl')


class ReplacePodmanToCtr(RegularPatch):
    def __init__(self) -> None:
        super().__init__("replace_podman_to_ctr")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch does following changes for containerd cri:
            1. Load ctr options file to control-plane and worker nodes
            2. Reinstall /usr/bin/etcdctl thirdparty to use ctr tool inside
            """.rstrip()
        )
