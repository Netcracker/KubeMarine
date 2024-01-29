from collections import OrderedDict
from typing import List

from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources


def deploy_kubernetes_reconfigure(cluster: KubernetesCluster) -> None:
    pass


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
