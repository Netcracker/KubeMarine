from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import sysctl

class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set sysctl variables")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()

        node_group = cluster.make_group_from_roles(['control-plane', 'worker'])
        node_group.call(sysctl.configure)
        node_group.call(sysctl.reload)
        

class SetSysctlVariables(RegularPatch):
    def __init__(self) -> None:
        super().__init__("set_sysctl_variables")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch sets kernel variables with sysctl at the control-plane, worker nodes according to the new defaults.
            """.rstrip()
        )
