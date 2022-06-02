from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self):
        super().__init__("patch inventory", recreate_inventory=True)

    def run(self, res: DynamicResources):
        res.formatted_inventory()["new_prop"] = "new val"


class PatchInventory(Patch):
    def __init__(self):
        super().__init__("patch_inventory")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return "Add new property to the inventory"
