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
        super().__init__("Correct ingress-nginx on kubernetes v1.25.x")

    def run(self, res: DynamicResources):
        cluster = res.cluster()

        version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
        if '.'.join(version.split('.')[:-1]) != 'v1.25':
            cluster.log.info(f"Patch is not relevant for kubernetes {version}")
            return

        nginx_ingress_plugin = cluster.inventory['plugins']['nginx-ingress-controller']
        if not nginx_ingress_plugin.get('install', False) \
                or nginx_ingress_plugin.get('installation', {}).get('procedures') is None:
            cluster.log.info("nginx-ingress-controller plugin is disabled or its procedures aren't defined")
            return

        cluster.log.info(f"The following plugins will be reinstalled: nginx-ingress-controller")
        plugins.install_plugin(cluster, 'nginx-ingress-controller', nginx_ingress_plugin['installation']['procedures'])



class FixNginxIngress(Patch):
    def __init__(self):
        super().__init__("correct_ingress_nginx")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reinstall nginx-ingress-controller plugin for kubernetes clusters on v1.25.X using corrected template.
            """.rstrip()
        )
