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
from kubemarine.procedures.install import deploy_loadbalancer_haproxy_configure
from kubemarine import plugins


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Enable proxy protocol for fullHA cluster")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        if all('balancer' not in node['roles'] for node in cluster.inventory['nodes']) or \
                any(len(node['roles']) > 1 for node in cluster.inventory['nodes'] if 'balancer' in node['roles']):
            cluster.log.debug("Cluster doesn't contain balancers or balancer role is combined with other roles. "
                              "Skip proxy-protocol enabling")
            return

        cluster.log.info("Reconfigure haproxy")
        deploy_loadbalancer_haproxy_configure(cluster)

        ingress_nginx_plugin = cluster.inventory['plugins']['nginx-ingress-controller']
        if not ingress_nginx_plugin.get('install', False) \
                or ingress_nginx_plugin.get('installation', {}).get('procedures') is None:
            cluster.log.info("nginx-ingress-controller plugin is disabled or its procedures aren't defined")
            return

        cluster.log.info(f"nginx-ingress-controller will be reinstalled")
        plugins.install_plugin(cluster, 'nginx-ingress-controller', ingress_nginx_plugin['installation']['procedures'])


class EnableProxyProtocol(RegularPatch):
    def __init__(self) -> None:
        super().__init__("enable_proxy_protocol_fullha_scheme")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch enables proxy protocol in ingress-nginx and haproxy (by default it's enabled by kubemarine),
            if cluster is in fullHA scheme.
            The patch does following steps:
            1. Reconfigure HAProxy
            2. Redeploy nginx-ingress-controller plugin
            """.rstrip()
        )
