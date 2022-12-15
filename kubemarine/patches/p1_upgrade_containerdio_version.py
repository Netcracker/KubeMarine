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
from kubemarine import cri
from kubemarine import packages


class TheAction(Action):
    def __init__(self):
        super().__init__("Upgrade containerd.io version")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        # check the OS family
        if cluster.get_os_family() == 'debian':
            # check CRI
            if cluster.inventory['services']['cri']['containerRuntime']:
                # get installed version
                group = cluster.nodes['all'].get_accessible_nodes()
                result = packages.detect_installed_packages_version_groups(group, 'containerd.io')
                version = list(result['containerd.io'])[0].split('=')[1]
                if '.'.join(version.split('.')[:2]) == '1.4':
                    group.call(cri.install)
                else:
                    cluster.log.debug("Cluster has applicable \"containerd.io\" version")
            else:
                cluster.log.debug("Cluster has \"Containerd\" as a CRI, so the \"containerd.io\" upgrade is not needed")
        else:
            cluster.log.debug("Cluster has different OS family, so the \"containerd.io\" upgrade is not needed")


class UpgrateContainerdioVersion(Patch):
    def __init__(self):
        super().__init__("upgrade_containerdio_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return """\
Upgrade containerd.io to v1.5.* for kubernetes clusters
Equivalent to 'kubemarine install --tasks=prepare.cri' for that clusters."""
