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
from typing import Optional, List

from kubemarine import kubernetes, haproxy, keepalived
from kubemarine.core import flow, summary
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install, add_node


def _get_active_nodes(node_type: str, cluster: KubernetesCluster) -> Optional[NodeGroup]:
    all_nodes = None
    if cluster.nodes.get(node_type) is not None:
        all_nodes = cluster.nodes[node_type].get_nodes_for_removal()
    if all_nodes is None or all_nodes.is_empty():
        cluster.log.debug("Skipped - no %s to remove" % node_type)
        return None
    active_nodes = all_nodes.get_online_nodes(True)
    disabled_nodes = all_nodes.exclude_group(active_nodes)
    if active_nodes.is_empty():
        cluster.log.debug("Skipped - %s nodes are inactive: %s" % (node_type, ", ".join(disabled_nodes.nodes)))
        return None
    if not disabled_nodes.is_empty():
        cluster.log.debug("Partly Skipped - several %s nodes are inactive: %s"
                          % (node_type, ", ".join(disabled_nodes.nodes)))
    return active_nodes


def loadbalancer_remove_haproxy(cluster: KubernetesCluster) -> None:
    nodes = _get_active_nodes("balancer", cluster)
    if nodes is None:
        return
    nodes.call(haproxy.disable)


def loadbalancer_remove_keepalived(cluster: KubernetesCluster) -> None:
    nodes = _get_active_nodes("keepalived", cluster)
    if nodes is None:
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

    nodes_for_removal = cluster.nodes['all'].get_nodes_for_removal()
    final_nodes = cluster.nodes['all'].get_final_nodes()

    # check if there are no more hosts where keepalived installed - remove according vrrp_ips
    for i, item in enumerate(inventory_to_finalize.get('vrrp_ips', [])):
        if 'hosts' in item:
            hosts = item['hosts']
        else:
            from kubemarine import keepalived
            hosts = keepalived.get_default_node_names(inventory_to_finalize)

        for host in hosts:
            host_name = host
            if isinstance(host_name, dict):
                host_name = host['name']
            if not final_nodes.has_node(host_name):
                hosts.remove(host)
        if not hosts:
            del inventory_to_finalize['vrrp_ips'][i]
        else:
            if inventory_to_finalize['vrrp_ips'][i].get('hosts', []):
                inventory_to_finalize['vrrp_ips'][i]['hosts'] = hosts

    # remove nodes from inventory if they in nodes for removal
    size = len(inventory_to_finalize['nodes'])
    for i in range(size):
        for j, node in enumerate(inventory_to_finalize['nodes']):
            if nodes_for_removal.has_node(node["name"]):
                del inventory_to_finalize['nodes'][j]
                break

    if inventory_to_finalize.get('services', {}).get('kubeadm', {}).get('apiServer', {}).get('certSANs'):
        for node in nodes_for_removal.get_ordered_members_configs_list():
            hostnames = [node['name'], node['internal_address']]
            if node.get('address') is not None:
                hostnames.append(node['address'])
            for name in hostnames:
                if name in inventory_to_finalize['services']['kubeadm']['apiServer']['certSANs']:
                    inventory_to_finalize['services']['kubeadm']['apiServer']['certSANs'].remove(name)

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
