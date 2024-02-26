from textwrap import dedent
from io import StringIO

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes, plugins
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity
 
class TheAction(Action):
    def __init__(self):
        super().__init__("Disable automount of Serice acocunt tokens")
    
    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster() 
        cluster.log.debug("As part of this patch, all the plugins will be redpeloyed")
        plugins.install(cluster)      


class DisableTokenAutomount(RegularPatch):
    def __init__(self):
        super().__init__("disable_token_automount")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Patch to redeploy of plugins to disable automounting of service account tokens
            """.rstrip()
        )