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
from kubemarine import plugins 


class TheAction(Action):
    def __init__(self):
        super().__init__("Upgrade calico version")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        if '.'.join(version.split('.')[:-1]) in ['v1.22', 'v1.23', 'v1.24']:
            calico_plugin = cluster.inventory['plugins']['calico']
            if not calico_plugin.get('install', False) or calico_plugin.get('installation', {}).get('procedures') is None:
                cluster.log.debug("Calico plugin is disabled or its procedures aren't defined")
            else:
                cluster.log.debug(f"The following plugins will be installed: calico")
                plugins.install_plugin(cluster, 'calico', calico_plugin['installation']['procedures'])
        else:
            cluster.log.debug(f"Skip opgrate for kubernetes version {version}")


class UpgrateCalicoVersion(Patch):
    def __init__(self):
        super().__init__("upgrade_calico_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Upgrade calico plugin to v3.24.1 for kubernetes clusters on v1.22.X or v1.23.X or v1.24.X.
Note that you may probably need to update plugins.calico section preliminarily.
Equivalent to 'kubemarine install --tasks=deploy.plugins' for that clusters."""