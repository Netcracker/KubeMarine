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
from kubemarine import thirdparties


class TheAction(Action):
    def __init__(self):
        super().__init__("Upgrade calico version")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        if '.'.join(version.split('.')[:-1]) == 'v1.24':
            crictl_thirdparty = cluster.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
            if cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
                cluster.log.debug("Thirdparty \"crictl\" will be upgraded")
                thirdparties.install_thirdparty(cluster, '/usr/bin/crictl.tar.gz')
            else:
                cluster.log.debug("Cluster has \"Docker\" as a CRI, so the \"crictl\" is not used")
        else:
            cluster.log.debug(f"Skip opgrate for kubernetes version {version}")


class UpgrateCrictlVersion(Patch):
    def __init__(self):
        super().__init__("upgrade_crictl_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Upgrade crictl thirdparty to v1.25.0 for kubernetes clusters on v1.24.X.
Note that you may probably need to update services.thirdparties section preliminarily.
Equivalent to 'kubemarine install --tasks=prepare.thirdparties' for that clusters."""
