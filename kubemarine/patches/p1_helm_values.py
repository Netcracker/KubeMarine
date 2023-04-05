from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self):
        super().__init__("Migrate helm values in plugins")

    def run(self, res: DynamicResources):
        inventory = res.formatted_inventory()
        for plugin, plugin_item in inventory.get('plugins', {}).items():
            for i, step in enumerate(plugin_item.get('installation', {}).get('procedures', [])):
                for apply_type, config in step.items():
                    # check if helm procedure type has both 'values' and 'values_file'
                    if apply_type == 'helm' and {'values', 'values_file'}.issubset(config.keys()):
                        res.logger().info(f"Remove unused 'values_file' property "
                                          f"for plugin {plugin!r} at installation step {i}.")
                        del config['values_file']
                        self.recreate_inventory = True

        if not self.recreate_inventory:
            res.logger().info("Nothing has changed")


class HelmValues(Patch):
    def __init__(self):
        super().__init__("helm_values")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            KubeMarine used to allow both 'values' and 'values_file' in helm procedure types of plugins,
            but only 'values' was picked up in this case.
            Now both sections can be used, and they will be picked up.
            The patch migrates old inventories with possible wrong configurations.
            """.rstrip()
        )
