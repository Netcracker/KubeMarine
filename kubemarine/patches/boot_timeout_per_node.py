from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Move globals.nodes.boot.timeout to per-node configuration")

    def run(self, res: DynamicResources) -> None:
        inventory = res.inventory()

        if 'boot' in inventory.get('globals', {}).get('nodes', {}):
            self.recreate_inventory = True
            inventory.setdefault('node_defaults', {})['boot'] = inventory['globals']['nodes'].pop('boot')
        else:
            res.logger().info("Nothing has changed")


class TimeoutPerNode(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("boot_timeout_per_node")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Move globals.nodes.boot.timeout to node_defaults.boot.timeout
            """.rstrip()
        )
