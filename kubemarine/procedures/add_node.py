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
import collections
import copy

from typing import Any, OrderedDict, List

from kubemarine import kubernetes, packages, plugins
from kubemarine.core import flow, utils
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.plugins.nginx_ingress import redeploy_ingress_nginx_is_needed
from kubemarine.procedures import install


def deploy_kubernetes_join(cluster: KubernetesCluster) -> None:

    group = cluster.make_group_from_roles(['control-plane', 'worker']).get_new_nodes()

    if group.is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    cluster.nodes['control-plane'].get_new_nodes().call(kubernetes.join_new_control_plane)

    if "worker" in cluster.nodes:
        cluster.nodes['worker'].get_new_nodes().exclude_group(cluster.nodes['control-plane']) \
            .call(kubernetes.init_workers)

    group.call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])

    cluster.log.debug("Waiting for new kubernetes nodes...")
    kubernetes.wait_for_nodes(group)
    kubernetes.schedule_running_nodes_report(cluster)


def redeploy_plugins_if_needed(cluster: KubernetesCluster) -> None:
    # redeploy ingress-nginx-controller if needed
    if redeploy_ingress_nginx_is_needed(cluster):
        cluster.log.debug("Redeploy ingress-nginx-controller plugin")
        plugins.install_plugin(cluster, 'nginx-ingress-controller',
                               cluster.inventory['plugins']['nginx-ingress-controller']['installation']['procedures'])
    else:
        cluster.log.debug("Redeploy ingress-nginx-controller is not needed, skip it")


def add_node_finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'add_node':
        return inventory_to_finalize

    new_nodes = cluster.nodes['all'].get_new_nodes()

    # add nodes to inventory if they in new nodes
    for new_node in new_nodes.get_ordered_members_list():
        new_node_name = new_node.get_node_name()
        new_node_found = False
        for i, node in enumerate(inventory_to_finalize['nodes']):
            if node['name'] == new_node_name:
                # new node already presented in final inventory - ok, just remove label
                if 'add_node' in inventory_to_finalize['nodes'][i]['roles']:
                    inventory_to_finalize['nodes'][i]['roles'].remove('add_node')
                new_node_found = True
                break

        # new node is not presented in final inventory - let's add it original config
        if not new_node_found:
            node_config = None

            # search for new node config in procedure inventory
            if cluster.procedure_inventory.get('nodes', {}):
                for node_from_procedure in cluster.procedure_inventory['nodes']:
                    if node_from_procedure['name'] == new_node_name:
                        node_config = node_from_procedure
                        break
            # maybe new nodes from other places?

            if node_config is None:
                raise Exception('Not possible to find new node config for final inventory')
            inventory_to_finalize["nodes"].append(node_config)

    # maybe merge vrrp ips only when adding?
    if "vrrp_ips" in cluster.procedure_inventory:
        utils.merge_vrrp_ips(cluster.procedure_inventory, inventory_to_finalize)

    return inventory_to_finalize


def cache_installed_packages(cluster: KubernetesCluster) -> None:
    """
    Task which is used to collect already installed packages versions on already existing nodes.
    It is called first during "add_node" procedure,
    so that new nodes install exactly the same packages as on other already existing nodes.
    """
    packages.cache_package_versions(cluster, cluster.inventory, by_initial_nodes=True)


tasks: OrderedDict[str, Any] = collections.OrderedDict(copy.deepcopy(install.tasks))
del tasks["deploy"]["accounts"]
tasks["deploy"]["plugins"] = redeploy_plugins_if_needed
tasks["deploy"]["kubernetes"]["init"] = deploy_kubernetes_join
tasks["cache_packages"] = cache_installed_packages
tasks.move_to_end("cache_packages", last=False)


class AddNodeAction(Action):
    def __init__(self) -> None:
        super().__init__('add node', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks, cumulative_points=install.cumulative_points)
        res.make_final_inventory()


def create_context(cli_arguments: List[str] = None) -> dict:

    cli_help = '''
    Script for adding node to Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='add_node')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([AddNodeAction()]).run_flow(context)


if __name__ == '__main__':
    main()
