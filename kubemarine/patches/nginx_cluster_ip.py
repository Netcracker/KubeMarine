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

from kubemarine import plugins
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources


class NginxClusterIPAction(Action):
    def __init__(self) -> None:
        super().__init__("Action to apply ingress nginx patch")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        plugins.install(cluster, {'nginx-ingress-controller': cluster.inventory['plugins']['nginx-ingress-controller']})


class NginxClusterIPPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__("nginx_cluster_ip")

    @property
    def action(self) -> Action:
        return NginxClusterIPAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch changes ingress nginx Service type from LoadBalancer to ClusterIP.
            This is safe change, because we actually do not rely on LoadBalancer type.
            LoadBalancer type actually causes problems if cloud controller manager is installed. 
            """.rstrip()
        )