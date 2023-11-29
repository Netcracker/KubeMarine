from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Set previous default Kubernetes version")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        inventory = res.formatted_inventory()
        if 'kubernetesVersion' not in inventory.get('services', {}).get('kubeadm', {}):
            logger.debug("Set services.kubeadm.kubernetesVersion = v1.26.7 in the inventory")
            inventory.setdefault('services', {}).setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.26.7'
            self.recreate_inventory = True
        else:
            logger.info("Skipping the patch as services.kubeadm.kubernetesVersion is explicitly provided.")


class PinKubernetesVersion(InventoryOnlyPatch):
    def __init__(self) -> None:
        super().__init__("pin_kubernetes_version")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            The patch sets previous default Kubernetes version in the inventory if the version was not explicitly specified.
            """.rstrip()
        )
