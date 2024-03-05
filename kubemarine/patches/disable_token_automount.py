from textwrap import dedent
from io import StringIO
from typing import List
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.plugins import install 
from kubemarine.plugins.manifest import Processor, EnrichmentFunction, Manifest, Identity
 
class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Disable automount of Serice acocunt tokens")
    
    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster() 
        def redeploy_oob_plugins(cluster: KubernetesCluster, plugin_names: List[str]) -> None:
            plugins = cluster.inventory["plugins"]
            specific_plugins = {name: plugins[name] for name in plugin_names if name in plugins}
            install(cluster, specific_plugins)
        cluster.log.debug("As part of this patch, all the OOB plugins will be redeployed")
        oob_plugins = ["calico", "nginx-ingress-controller", "kubernetes-dashboard", "local-path-provisioner" ]  # List of plugins to install
        redeploy_oob_plugins(cluster, oob_plugins)     


class DisableTokenAutomount(RegularPatch):
    def __init__(self) -> None:
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