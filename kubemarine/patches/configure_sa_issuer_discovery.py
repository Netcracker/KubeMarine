from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes_accounts


class ConfigureSAIssuerDiscoveryAction(Action):
    def __init__(self) -> None:
        super().__init__("Configure SA Issuer Discovery")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        kubernetes_accounts.handle_authenticated_sa_issuer_discovery(cluster)


class ConfigureSAIssuerDiscovery(RegularPatch):
    def __init__(self) -> None:
        super().__init__("configure_sa_issuer_discovery")

    @property
    def action(self) -> Action:
        return ConfigureSAIssuerDiscoveryAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            This patch applies new default parameter rbac.authenticated-issuer-discovery.
            By default, it will allow unauthenticated access to service account issuer discovery endpoint.
            """.rstrip()
        )