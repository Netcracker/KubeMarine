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

from kubemarine import kubernetes, haproxy, keepalived
from kubemarine.core import flow, summary
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install, add_node


def get_active_nodes(node_type: str, cluster: KubernetesCluster) -> NodeGroup:
    all_nodes = cluster.make_group_from_roles([node_type]).get_nodes_for_removal()
    if all_nodes.is_empty():
        cluster.log.debug("Skipped - no %s to remove" % node_type)
        return all_nodes
    active_nodes = all_nodes.get_online_nodes(True)
    disabled_nodes = all_nodes.exclude_group(active_nodes)
    if active_nodes.is_empty():
        cluster.log.debug("Skipped - %s nodes are inactive: %s" % (node_type, ", ".join(disabled_nodes.nodes)))
        return active_nodes
    if not disabled_nodes.is_empty():
        cluster.log.debug("Partly Skipped - several %s nodes are inactive: %s"
                          % (node_type, ", ".join(disabled_nodes.nodes)))
    return active_nodes


def loadbalancer_remove_haproxy(cluster: KubernetesCluster) -> None:
    nodes = get_active_nodes("balancer", cluster)
    if nodes.is_empty():
        return
    nodes.call(haproxy.disable)


def loadbalancer_remove_keepalived(cluster: KubernetesCluster) -> None:
    nodes = get_active_nodes("keepalived", cluster)
    if nodes.is_empty():
        return
    nodes.call(keepalived.disable)


def remove_kubernetes_nodes(cluster: KubernetesCluster) -> None:
    group = cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_for_removal()

    if group.is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.call(kubernetes.reset_installation_env)
    kubernetes.schedule_running_nodes_report(cluster)


def remove_node_finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'remove_node':
        return inventory_to_finalize

    final_nodes = cluster.nodes['all'].get_final_nodes()

    is_finalization = any('remove_node' in node['roles'] for node in inventory_to_finalize['nodes'])

    if not is_finalization:
        kubernetes.remove_node_enrichment(inventory_to_finalize, cluster)

    # Do not remove VRRP IPs and do not change their assigned hosts.
    # If the assigned host does not exist or is not a balancer, it will be just skipped.
    # Though it is necessary to remove hosts from the VRRP IP of finalized inventory if they were enriched ourselves.
    if is_finalization:
        for i, item in enumerate(inventory_to_finalize.get('vrrp_ips', [])):
            raw_item = cluster.raw_inventory['vrrp_ips'][i]
            # If redefined, it was not enriched. See keepalived.enrich_inventory_apply_defaults().
            if not isinstance(raw_item, str) and 'hosts' in raw_item:
                continue

            item['hosts'] = [host for host in item['hosts'] if final_nodes.has_node(host['name'])]

    # remove nodes from inventory if they in nodes for removal
    size = len(inventory_to_finalize['nodes'])
    for i in range(size):
        for j, node in enumerate(inventory_to_finalize['nodes']):
            if 'remove_node' in node['roles']:
                del inventory_to_finalize['nodes'][j]
                break

    return inventory_to_finalize


tasks = OrderedDict({
    "loadbalancer": {
        "remove": {
            "haproxy": loadbalancer_remove_haproxy,
            "keepalived": loadbalancer_remove_keepalived
        },
        "configure": {
            "haproxy": install.deploy_loadbalancer_haproxy_configure,
            "keepalived": install.deploy_loadbalancer_keepalived_configure
        },
    },
    "update": {
        "etc_hosts": install.system_prepare_dns_etc_hosts,
        "coredns": install.deploy_coredns,
        "plugins": add_node.redeploy_plugins_if_needed,
    },
    "remove_kubernetes_nodes": remove_kubernetes_nodes,
    "overview": install.overview,
})


cumulative_points = {
    summary.exec_delayed: [
        flow.END_OF_TASKS
    ]
}


class RemoveNodeAction(Action):
    def __init__(self) -> None:
        super().__init__('remove node', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks, cumulative_points=cumulative_points)
        res.make_final_inventory()


def create_context(cli_arguments: List[str] = None) -> dict:

    cli_help = '''
    Script for removing node from Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='remove_node')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([RemoveNodeAction()]).run_flow(context)


if __name__ == '__main__':
    main()
