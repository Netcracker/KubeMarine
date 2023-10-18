#!/usr/bin/env python3
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


from collections import OrderedDict
from typing import List

from kubemarine import plugins, k8s_certs
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.plugins import calico


def renew_nginx_ingress_certs_task(cluster: KubernetesCluster) -> None:
    # check that renewal is required for nginx
    if not cluster.procedure_inventory.get("nginx-ingress-controller"):
        cluster.log.debug("Skipped: nginx ingress controller certs renewal is not required")
        return

    cluster.log.debug("Starting certificate renewal for nginx ingress controller, plugin will be reinstalled")
    plugin = cluster.inventory["plugins"]["nginx-ingress-controller"]
    # If by chance default certificate is not previously configured,
    # the procedure reconfigures the DeamonSet as well.
    plugins.install_plugin(cluster, "nginx-ingress-controller", plugin["installation"]['procedures'])


def renew_calico_apiserver_certs_task(cluster: KubernetesCluster) -> None:
    # check that renewal is required for the Calico API server
    if 'calico' not in cluster.procedure_inventory:
        cluster.log.debug("Skipped: Calico API server certs renewal is not required")
        return

    # Let's assume that if the user specified `calico` section in the procedure inventory,
    # they agree with the default renew procedure.
    # Also, it implies that the `calico` plugin is enabled and installed, and Calico API server is enabled.
    calico.renew_apiserver_certificate(cluster)


def k8s_certs_renew_task(cluster: KubernetesCluster) -> None:
    if not cluster.procedure_inventory.get("kubernetes"):
        cluster.log.debug("Skipped: kubernetes certs renewal is not required")
        return

    cluster.log.debug("Starting certificate renewal for kubernetes")
    cluster.nodes['control-plane'].call(k8s_certs.renew_apply)


def k8s_certs_overview_task(cluster: KubernetesCluster) -> None:
    cluster.nodes['control-plane'].call(k8s_certs.k8s_certs_overview)


tasks = OrderedDict({
    "kubernetes": k8s_certs_renew_task,
    "nginx_ingress_controller": renew_nginx_ingress_certs_task,
    "calico": renew_calico_apiserver_certs_task,
    "certs_overview": k8s_certs_overview_task
})


class CertRenewAction(Action):
    def __init__(self) -> None:
        super().__init__('cert renew', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def create_context(cli_arguments: List[str] = None) -> dict:

    cli_help = '''
    Script for certificates renewal on existing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='cert_renew')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([CertRenewAction()]).run_flow(context)


if __name__ == '__main__':
    main()
