#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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

from kubetool import kubernetes, haproxy, keepalived, coredns
from kubetool.core import flow
from kubetool.core.cluster import KubernetesCluster
from kubetool.core.group import NodeGroup
from kubetool.procedures import install


def _get_active_nodes(node_type: str, cluster: KubernetesCluster) -> NodeGroup:
    all_nodes = None
    if cluster.nodes.get(node_type) is not None:
        all_nodes = cluster.nodes[node_type].get_nodes_for_removal()
    if all_nodes is None or all_nodes.is_empty():
        cluster.log.debug("Skipped - no %s to remove" % node_type)
        return
    active_nodes = all_nodes.get_online_nodes()
    disabled_nodes = all_nodes.exclude_group(active_nodes)
    if active_nodes.is_empty():
        cluster.log.debug("Skipped - %s nodes are inactive: %s" % (node_type, ", ".join(disabled_nodes.nodes.keys())))
        return
    if not disabled_nodes.is_empty():
        cluster.log.debug("Partly Skipped - several %s nodes are inactive: %s"
                          % (node_type, ", ".join(disabled_nodes.nodes.keys())))
    return active_nodes


def loadbalancer_remove_haproxy(cluster: KubernetesCluster):
    nodes = _get_active_nodes("balancer", cluster)
    if nodes is None:
        return
    nodes.call(haproxy.disable)


def loadbalancer_remove_keepalived(cluster: KubernetesCluster):
    nodes = _get_active_nodes("keepalived", cluster)
    if nodes is None:
        return
    nodes.call(keepalived.disable)


def remove_kubernetes_nodes(cluster: KubernetesCluster):
    cluster.nodes['master'].include_group(cluster.nodes.get('worker')).get_nodes_for_removal() \
        .call(kubernetes.reset_installation_env)


def remove_node_finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize):
    if cluster.context.get('initial_procedure') != 'remove_node':
        return inventory_to_finalize

    nodes_for_removal = cluster.nodes['all'].get_nodes_for_removal()
    final_nodes = cluster.nodes['all'].get_final_nodes()

    # check if there are no more hosts where keepalived installed - remove according vrrp_ips
    for i, item in enumerate(inventory_to_finalize.get('vrrp_ips', [])):
        if 'hosts' in item:
            hosts = item['hosts']
        else:
            from kubetool import keepalived
            hosts = keepalived.get_default_node_names(inventory_to_finalize)

        for host in hosts:
            host_name = host
            if isinstance(host_name, dict):
                host_name = host['name']
            if final_nodes.get_first_member(apply_filter={"name": host_name}) is None:
                hosts.remove(host)
        if not hosts:
            del inventory_to_finalize['vrrp_ips'][i]
        else:
            if inventory_to_finalize['vrrp_ips'][i].get('hosts', []):
                inventory_to_finalize['vrrp_ips'][i]['hosts'] = hosts

    # remove nodes from inventory if they in nodes for removal
    # todo deletion of elements from collection to iterate over!
    size = len(inventory_to_finalize['nodes'])
    for i in range(size):
        for j, node in enumerate(inventory_to_finalize['nodes']):
            if nodes_for_removal.has_node(node["name"]):
                del inventory_to_finalize['nodes'][j]
                break

    if inventory_to_finalize['services'].get('kubeadm', {}).get('apiServer', {}).get('certSANs'):
        for node in nodes_for_removal.get_ordered_members_list(provide_node_configs=True):
            hostnames = [node['name'], node['address'], node['internal_address']]
            for name in hostnames:
                if name in inventory_to_finalize['services']['kubeadm']['apiServer']['certSANs']:
                    inventory_to_finalize['services']['kubeadm']['apiServer']['certSANs'].remove(name)

    if inventory_to_finalize['services'].get('etc_hosts'):
        for node in nodes_for_removal.get_ordered_members_list(provide_node_configs=True):
            if inventory_to_finalize['services']['etc_hosts'].get(node['internal_address']):
                del inventory_to_finalize['services']['etc_hosts'][node['internal_address']]
            if inventory_to_finalize['services']['etc_hosts'].get(node['address']):
                del inventory_to_finalize['services']['etc_hosts'][node['address']]

        coredns.enrich_add_hosts_config(inventory_to_finalize, cluster)

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
        "coredns": install.deploy_coredns
    },
    "remove_kubernetes_nodes": remove_kubernetes_nodes,
    "overview": install.overview,
})


def main(cli_arguments=None):

    cli_help = '''
    Script for removing node from Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_parser(cli_help)
    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('procedure_config', metavar='procedure_config', type=str,
                        help='config file for remove_node procedure')

    if cli_arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    context = flow.create_context(args, procedure='remove_node',
                                  included_tasks=defined_tasks, excluded_tasks=defined_excludes)
    context['inventory_regenerate_required'] = True

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        procedure_inventory_filepath=args.procedure_config
    )


if __name__ == '__main__':
    main()
