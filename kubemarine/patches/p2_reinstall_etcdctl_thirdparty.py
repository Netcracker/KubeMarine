from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.thirdparties import install_thirdparty


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reinstall etcdctl thirdparty")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        cluster.log.info("Update /usr/bin/etcdctl thirdparty")
        install_thirdparty(cluster.nodes['all'], '/usr/bin/etcdctl')


class ReinstallEtcdctl(RegularPatch):
    def __init__(self) -> None:
        super().__init__("reinstall_etcdctl")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch reinstalls etcdctl thirdparty.
            """.rstrip()
        )
