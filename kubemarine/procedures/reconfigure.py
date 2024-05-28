# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict
from typing import List, Union

from ordered_set import OrderedSet

from kubemarine import kubernetes, sysctl, system
from kubemarine.core import flow
from kubemarine.core.cluster import KubernetesCluster


def system_prepare_system_sysctl(cluster: KubernetesCluster) -> None:
    group = cluster.nodes['all']

    # Even if services.sysctl is not supplied, the effective configuration may change
    # because it may depend on other services (kubelet config and patches).
    changes_detected = any(
        cluster.previous_nodes_inventory[host]['services']['sysctl'] != cluster.nodes_inventory[host]['services']['sysctl']
        for host in cluster.nodes['all'].get_hosts()
    )

    # Reconfigure kernel parameters even if empty section is supplied.
    # This allows to reconfigure the parameters based on manual changes in the inventory.
    # Take into account only `services.sysctl`, but not `patches`, because `patches` may reconfigure different services.
    if (cluster.procedure_inventory.get('services', {}).get('sysctl') is not None
            or changes_detected):
        cluster.log.debug(f"Detected changes in kernel parameters")

        # In comparison to installation, do not reboot & verify the parameters.
        # The parameters are closely tied to the other services' settings, e.g. kube-proxy, and may be changed together.
        # After reboot, if sysctl is reconfigured, but other services are not yet,
        # verification may fail, but the final inventory may still be correct after all.
        is_updated = group.call(sysctl.setup_sysctl)
        if is_updated:
            group.call(system.verify_sysctl)
    else:
        cluster.log.debug("No changes detected, skipping.")


def deploy_kubernetes_reconfigure(cluster: KubernetesCluster) -> None:
    changed_components = OrderedSet[str]()
    for component, constants in kubernetes.components.COMPONENTS_CONSTANTS.items():
        for section_names in constants['sections']:
            procedure_section: Union[dict, list, None] = cluster.procedure_inventory
            previous_section = cluster.previous_inventory
            section = cluster.inventory
            for name in section_names:
                if isinstance(procedure_section, dict):
                    procedure_section = procedure_section.get(name)

                previous_section = previous_section[name]
                section = section[name]

            # Even if section is not supplied, the effective configuration may change
            # because it may depend on other services (services.sysctl).
            changed_detected = previous_section != section

            # Consider component as changed even if empty section is supplied.
            # This allows to reconfigure the component based on manual changes in the inventory.
            if (procedure_section is not None
                    or changed_detected):
                changed_components.add(component)

    if changed_components:
        cluster.log.debug(f"Detected changes in components: {', '.join(changed_components)}")
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])
        kubernetes_nodes.call(kubernetes.components.reconfigure_components, components=list(changed_components))
    else:
        cluster.log.debug("No changes detected, skipping.")


tasks = OrderedDict({
    "prepare": {
        "system": {
            "sysctl": system_prepare_system_sysctl,
        },
    },
    "deploy": {
        "kubernetes": {
            "reconfigure": deploy_kubernetes_reconfigure
        }
    }
})


class ReconfigureAction(flow.TasksAction):
    def __init__(self) -> None:
        super().__init__('reconfigure', tasks, recreate_inventory=True)


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
        Script for generic reconfiguring of existing Kubernetes cluster.

        How to use:

        '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure="reconfigure")
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([ReconfigureAction()]).run_flow(context)


if __name__ == '__main__':
    main()
