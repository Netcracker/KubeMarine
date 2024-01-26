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
from kubemarine.core import flow
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.kubernetes import components
from kubemarine.plugins import calico
from kubemarine.procedures import install


def deploy_kubernetes_join(cluster: KubernetesCluster) -> None:

    group = cluster.get_new_nodes().having_roles(['control-plane', 'worker'])

    if group.is_empty():
        # If balancers are added, it is necessary to reconfigure apiServer.certSANs
        write_new_apiserver_certsans(cluster)
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.having_roles(['control-plane']).call(kubernetes.join_new_control_plane)
    group.having_roles(['worker']).exclude_group(cluster.nodes['control-plane']) \
        .call(kubernetes.init_workers)

    write_new_apiserver_certsans(cluster)

    group.call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])

    cluster.log.debug("Waiting for new kubernetes nodes...")
    kubernetes.wait_for_nodes(group)
    kubernetes.schedule_running_nodes_report(cluster)


def write_new_apiserver_certsans(cluster: KubernetesCluster) -> None:
    # If balancer or control plane is added, apiServer.certSANs are changed.
    # See kubernetes.enrich_inventory()
    new_nodes_require_sans = cluster.get_new_nodes().having_roles(['control-plane', 'balancer'])
    if new_nodes_require_sans.is_empty():
        return

    cluster.log.debug("Write new certificates for kube-apiserver")
    components.reconfigure_components(cluster.nodes['control-plane'], ['kube-apiserver/cert-sans'])


def redeploy_plugins_if_needed(cluster: KubernetesCluster) -> None:
    # redeploy_candidates is a source of plugins that may be redeployed.
    # Some plugins from redeploy_candidates will not be redeployed, because they have "install: false"
    redeploy_candidates = {}
    for plugin, plugin_item in cluster.inventory["plugins"].items():
        if (cluster.previous_inventory["plugins"][plugin] != plugin_item
                # New route reflectors are added with disabled fullmesh
                or (plugin == 'calico' and calico.new_route_reflectors_added(cluster))):
            cluster.log.debug(f"Configuration of {plugin!r} plugin has changed, scheduling it for redeploy")
            redeploy_candidates[plugin] = cluster.inventory["plugins"][plugin]

    plugins.install(cluster, redeploy_candidates)


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


class AddNodeAction(flow.TasksAction):
    def __init__(self) -> None:
        super().__init__('add node', tasks,
                         cumulative_points=install.cumulative_points, recreate_inventory=True)


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
