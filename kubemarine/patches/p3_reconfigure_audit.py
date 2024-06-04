from textwrap import dedent

from kubemarine.core import yaml_merger
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Reconfigure Kubernetes auditing")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        raw_cluster_policy = res.inventory().get('services', {}).get('audit', {}).get('cluster_policy', {})

        if ('rules' not in raw_cluster_policy
                or yaml_merger.is_list_extends(raw_cluster_policy['rules'],
                                               ['services', 'audit', 'cluster_policy', 'rules'])):
            install.run_tasks(res, ['deploy.kubernetes.audit'])
        else:
            return logger.info("Audit policy is redefined in the inventory file. Nothing to change.")


class ReconfigureAudit(RegularPatch):
    def __init__(self) -> None:
        super().__init__("reconfigure_audit")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Reconfigure Kubernetes auditing. Remove auditing of no longer supported podsecuritypolicies.
            
            The patch is equivalent to `kubemarine install --tasks deploy.kubernetes.audit`.
            """.rstrip()
        )
