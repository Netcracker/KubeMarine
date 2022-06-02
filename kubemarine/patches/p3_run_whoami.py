from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self):
        super().__init__("run whoami")

    def run(self, res: DynamicResources):
        whoami = res.cluster().nodes['all'].sudo("whoami")
        res.logger().info(whoami)


class RunWhoami(Patch):
    def __init__(self):
        super().__init__("run_whoami")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return 'Run whoami'
