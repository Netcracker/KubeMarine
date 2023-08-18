from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reconfigure Kubernetes audit policy")

    def run(self, res: DynamicResources) -> None:
        install.run_tasks(res, ['deploy.kubernetes.audit'])


class ReconfigureAuditPolicy(RegularPatch):
    def __init__(self) -> None:
        super().__init__("reconfigure_audit_policy")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reconfigure Kubernetes audit policy.
            To find new default target configuration, refer to kubemarine/resources/configurations/defaults.yaml
            - services.kubeadm.apiServer.extraArgs.audit-*
            - services.audit.cluster_policy
            The patch is equivalent to `kubemarine install --tasks deploy.kubernetes.audit`.
            """.rstrip()
        )
