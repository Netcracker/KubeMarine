from textwrap import dedent
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes.components import reconfigure_components

class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Update kubelet TLS cipher suites (if necessary)")

    def run(self, res: DynamicResources) -> None:
        kubernetes_nodes = res.cluster().make_group_from_roles(['worker'])
        reconfigure_components(kubernetes_nodes, ['kubelet'])

class UpdatekubeletCipherSuites(RegularPatch):
    def __init__(self) -> None:
        super().__init__("kubelet_cipher_suites")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Patch to update the kubelet TLS cipher suites.
            """.rstrip()
        )