from collections import OrderedDict
from typing import List, Union

from ordered_set import OrderedSet

from kubemarine import kubernetes
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources


def deploy_kubernetes_reconfigure(cluster: KubernetesCluster) -> None:
    changed_components = OrderedSet[str]()
    for component, constants in kubernetes.components.COMPONENTS_CONSTANTS.items():
        for section_names in constants['sections']:
            section: Union[dict, list, None] = cluster.procedure_inventory
            for name in section_names:
                if isinstance(section, dict):
                    section = section.get(name)

            if section is not None:
                changed_components.add(component)

    if changed_components:
        cluster.log.debug(f"Detected changes in components: {', '.join(changed_components)}")
        kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])
        kubernetes_nodes.call(kubernetes.components.reconfigure_components, components=list(changed_components))
    else:
        cluster.log.debug("No changes detected, skipping.")


tasks = OrderedDict({
    "deploy": {
        "kubernetes": {
            "reconfigure": deploy_kubernetes_reconfigure
        }
    }
})


class ReconfigureAction(Action):
    def __init__(self) -> None:
        super().__init__('reconfigure', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


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
