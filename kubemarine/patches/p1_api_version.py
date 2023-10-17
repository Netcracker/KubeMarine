from textwrap import dedent
from typing import cast

from ruamel.yaml import CommentedMap

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Insert API version to the inventory", recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        inventory = cast(CommentedMap, res.formatted_inventory())
        inventory.insert(0, 'apiVersion', 'v1')
        logger = res.logger()
        logger.warning("Inventory is patched, and you need to patch the procedure inventories manually if you use any.")


class InsertAPIVersion(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("api_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Inserts `apiVersion: v1` to the inventory.
            """.rstrip()
        )
