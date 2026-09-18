from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install

class ContainerdLimitNOFILEAction(Action):
    def run(self, res: DynamicResources) -> None:
        install.run_tasks(res, ['prepare.cri.configure'])

class ContainerdLimitNOFILEPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__("containerd_limitnofile")

    @property
    def action(self) -> Action:
        return ContainerdLimitNOFILEAction("containerd_limitnofile")

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch uploads containerd drop-in on all nodes 
            to configure containerd LimitNOFILE soft/hard limits.
            """.rstrip()
        )