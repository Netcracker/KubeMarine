from textwrap import dedent
from typing import cast

from kubemarine import plugins
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.plugins import builtin, manifest, calico


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Enable Calico Typha Metrics")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        logger = cluster.log

        if not builtin.is_manifest_installed(cluster, manifest.Identity('calico')):
            return logger.warning("Calico manifest is not installed using default procedure. The patch is skipped.")

        processor = cast(
            calico.CalicoManifestProcessor,
            builtin.get_manifest_processor(cluster.log, cluster.inventory, manifest.Identity('calico'))
        )
        if not processor.is_typha_enabled():
            return logger.info("The patch is skipped as Calico Typha is not enabled.")

        plugins.install(cluster, {'calico': cluster.inventory['plugins']['calico']})


class EnableCalicoTyphaMetrics(RegularPatch):
    def __init__(self) -> None:
        super().__init__("calico_typha_metrics")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            The patch enables and exposes the Calico Typha metrics via the Kubernetes service.
            
            Roughly equivalent to 'kubemarine install --tasks=deploy.plugins'
            with all plugins disabled except the 'calico'.
            """.rstrip()
        )
