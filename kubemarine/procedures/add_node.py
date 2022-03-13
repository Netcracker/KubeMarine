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


import copy
import os

from collections import OrderedDict
from kubemarine import kubernetes, system
from kubemarine.core import flow, utils
from kubemarine.procedures import install


def deploy_kubernetes_join(cluster):

    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker')).get_new_nodes()

    if cluster.context['initial_procedure'] == 'add_node' and group.is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    cluster.nodes['master'].get_new_nodes().call(kubernetes.join_new_master)

    if "worker" in cluster.nodes:
        cluster.nodes["worker"].get_new_nodes().new_group(apply_filter=lambda node: 'master' not in node['roles']) \
            .call(kubernetes.init_workers)

    group.call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])

    if group.is_empty():
        cluster.log.debug("Skipped: no kubernetes nodes to wait")
        return
    else:
        cluster.log.debug("Waiting for new kubernetes nodes...")
        kubernetes.wait_for_nodes(group)


def add_node_finalize_inventory(cluster, inventory_to_finalize):
    if cluster.context.get('initial_procedure') != 'add_node':
        return inventory_to_finalize

    new_nodes = cluster.nodes['all'].get_new_nodes()

    if new_nodes != None:
        cluster_storage = utils.ClusterStorage.get_instance(cluster)
        cluster_storage.collect_info_all_master()
        

    # add nodes to inventory if they in new nodes and transfer log on the new node
    for new_node in new_nodes.get_ordered_members_list(provide_node_configs=True):
        if 'master' in new_node['roles']:
                new_node['connection'].put(cluster.context['execution_arguments']['dump_location'] + "dump_log_cluster.tar.gz", os.path.join("/tmp/",'dump_log_cluster.tar.gz'), sudo=True, binary=False)
                new_node['connection'].sudo(f'tar -C / xzvf /tmp/dump_log_cluster.tar.gz')
        else:
            cluster.log.debug('Master not found')
        new_node_found = False
        for i, node in enumerate(inventory_to_finalize['nodes']):
            if node['name'] == new_node['name']:
                # new node already presented in final inventory - ok, just remove label
                if 'add_node' in inventory_to_finalize['nodes'][i]['roles']:
                    inventory_to_finalize['nodes'][i]['roles'].remove('add_node')
                    cluster.inventory['nodes'][i]['roles'].remove('add_node')
                new_node_found = True
                break

        # new node is not presented in final inventory - let's add it original config
        if not new_node_found:
            node_config = None

            # search for new node config in procedure inventory
            if cluster.procedure_inventory.get('nodes', {}):
                for node_from_procedure in cluster.procedure_inventory['nodes']:
                    if node_from_procedure['name'] == new_node['name']:
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


def cache_installed_packages(cluster):
    """
    Task which is used to collect already installed packages versions on already existing nodes.
    It is called first during "add_node" procedure,
    so that new nodes install exactly the same packages as on other already existing nodes.
    """

    # avoid caching when unchanged nodes are not equal to GLOBAL os
    global_os = system.get_os_family(cluster)
    for node in cluster.nodes['all'].get_unchanged_nodes().get_ordered_members_list(provide_node_configs=True):
        if cluster.context["nodes"][node['connect_to']]["os"]['family'] != global_os:
            cluster.log.debug(f"New node has different OS ({global_os}) "
                              f"than some other nodes ({cluster.context['nodes'][node['connect_to']]['os']['family']}), "
                              "packages will not be cached.")
            return

    cluster.cache_package_versions()


tasks = OrderedDict(copy.deepcopy(install.tasks))
del tasks["deploy"]["plugins"]
del tasks["deploy"]["accounts"]
tasks["deploy"]["kubernetes"]["init"] = deploy_kubernetes_join
tasks["cache_packages"] = cache_installed_packages
tasks.move_to_end("cache_packages", last=False)


def main(cli_arguments=None):

    cli_help = '''
    Script for adding node to Kubernetes cluster.

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
                        help='config file for add_node procedure')

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

    context = flow.create_context(args, procedure='add_node',
                                  included_tasks=defined_tasks, excluded_tasks=defined_excludes)
    context['inventory_regenerate_required'] = True

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        procedure_inventory_filepath=args.procedure_config,
        cumulative_points=install.cumulative_points
    )


if __name__ == '__main__':
    main()
