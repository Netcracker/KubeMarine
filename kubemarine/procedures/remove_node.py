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
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.procedures import install, add_node


def get_active_nodes(node_type: str, cluster: KubernetesCluster) -> NodeGroup:
    all_nodes = cluster.get_nodes_for_removal().having_roles([node_type])
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
    group = cluster.get_nodes_for_removal().having_roles(['control-plane', 'worker'])

    if group.is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.call(kubernetes.reset_installation_env)
    kubernetes.schedule_running_nodes_report(cluster)


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


class RemoveNodeAction(flow.TasksAction):
    def __init__(self) -> None:
        super().__init__('remove node', tasks,
                         cumulative_points=cumulative_points, recreate_inventory=True)


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
