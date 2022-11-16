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

from collections import OrderedDict
from kubemarine import kubernetes, system
from kubemarine.core import flow, utils
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


def deploy_kubernetes_join(cluster):

    group = cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker')).get_new_nodes()

    if cluster.context['initial_procedure'] == 'add_node' and group.is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    cluster.nodes['control-plane'].get_new_nodes().call(kubernetes.join_new_control_plane)

    if "worker" in cluster.nodes:
        cluster.nodes["worker"].get_new_nodes().new_group(apply_filter=lambda node: 'control-plane' not in node['roles']) \
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

    # add nodes to inventory if they in new nodes
    for new_node in new_nodes.get_ordered_members_list(provide_node_configs=True):
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
    unique_os = set(((cluster.context['nodes'][node['connect_to']]['os']['family']), (cluster.context['nodes'][node['connect_to']]['os']['version']))
               for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True))
    different_os = len(unique_os)

    if different_os > 1:
        cluster.log.debug(f"New node has different OS"
                          f" than some other nodes, "
                          "packages will not be cached.")
        cluster.log.debug("Count different OS %d ", different_os)
        cluster.log.debug("Unique OS %s ", unique_os)

        return
    # Cache packages only if it's set in configuration
    if cluster.inventory['services']['packages']['cache_versions']:
        cluster.cache_package_versions()


tasks = OrderedDict(copy.deepcopy(install.tasks))
del tasks["deploy"]["plugins"]
del tasks["deploy"]["accounts"]
tasks["deploy"]["kubernetes"]["init"] = deploy_kubernetes_join
tasks["cache_packages"] = cache_installed_packages
tasks.move_to_end("cache_packages", last=False)


class AddNodeAction(Action):
    def __init__(self):
        super().__init__('add node', recreate_inventory=True)

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks, cumulative_points=install.cumulative_points)
        res.make_final_inventory()


def main(cli_arguments=None):

    cli_help = '''
    Script for adding node to Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help)
    context = flow.create_context(parser, cli_arguments, procedure='add_node')

    flow.run_actions(context, [AddNodeAction()])


if __name__ == '__main__':
    main()
