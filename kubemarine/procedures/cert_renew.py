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

from kubemarine import plugins, k8s_certs
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources


def renew_nginx_ingress_certs_task(cluster):
    # check that renewal is required for nginx
    if not cluster.procedure_inventory.get("nginx-ingress-controller"):
        cluster.log.debug("Skipped: nginx ingress controller certs renewal is not required")
        return

    cluster.log.debug("Starting certificate renewal for nginx ingress controller, plugin will be reinstalled")
    plugin = cluster.inventory["plugins"]["nginx-ingress-controller"]
    plugins.install_plugin(cluster, "nginx-ingress-controller", plugin["installation"]['procedures'])


def k8s_certs_renew_task(cluster):
    if not cluster.procedure_inventory.get("kubernetes"):
        cluster.log.debug("Skipped: kubernetes certs renewal is not required")
        return

    cluster.log.debug("Starting certificate renewal for kubernetes")
    cluster.nodes['control-plane'].call(k8s_certs.renew_apply)


def k8s_certs_overview_task(cluster):
    cluster.nodes['control-plane'].call(k8s_certs.k8s_certs_overview)


tasks = OrderedDict({
    "kubernetes": k8s_certs_renew_task,
    "nginx_ingress_controller": renew_nginx_ingress_certs_task,
    "certs_overview": k8s_certs_overview_task
})


class CertRenewAction(Action):
    def __init__(self):
        super().__init__('cert renew', recreate_inventory=True)

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def main(cli_arguments=None):

    cli_help = '''
    Script for certificates renewal on existing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='cert_renew')

    flow.run_actions(context, [CertRenewAction()])


if __name__ == '__main__':
    main()
