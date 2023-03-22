from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch
from kubemarine.core.resources import DynamicResources
from kubemarine import plugins


class TheAction(Action):
    def __init__(self):
        super().__init__("Calico fixes")

    def run(self, res: DynamicResources):
        cluster = res.cluster()
        calico_plugin = cluster.inventory['plugins']['calico']
        if not calico_plugin.get('install', False) \
                or calico_plugin.get('installation', {}).get('procedures') is None:
            cluster.log.info("Calico plugin is disabled or its procedures aren't defined")
            return

        cluster.log.info(f"Calico will be reinstalled")
        plugins.install_plugin(cluster, 'calico', calico_plugin['installation']['procedures'])


class CalicoFixes(Patch):
    def __init__(self):
        super().__init__("calico_fixes")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reinstall calico plugin. Correct environment variables of 'calico-node' pods.
            """.rstrip()
        )
