from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self):
        super().__init__("Update user inventory to keep backward-compatible resources requests/limits for plugins")

    def run(self, res: DynamicResources):
        inventory = res.formatted_inventory()

        self.recreate_inventory = True
        local_path_provisioner = inventory.get("plugins", {}).get("local-path-provisioner", {})
        if local_path_provisioner.get("install", False):
            local_path_provisioner["resources"] = {}

        nginx_ingress = inventory.get("plugins", {}).get("nginx-ingress-controller", {})
        if nginx_ingress.get("install", False):
            nginx_ingress.setdefault("controller", {})["resources"] = {"requests": {"cpu": "100m", "memory": "90Mi"}}
            nginx_ingress.setdefault("webhook", {})["resources"] = {}

        kubernetes_dashboard = inventory.get("plugins", {}).get("kubernetes-dashboard", {})
        if kubernetes_dashboard.get("install", False):
            kubernetes_dashboard.setdefault("dashboard", {})["resources"] = {}
            kubernetes_dashboard.setdefault("metrics-scraper", {})["resources"] = {}

        calico = inventory.get("plugins", {}).get("calico", {})
        if calico.get("install", False):
            calico.setdefault("node", {})["resources"] = {"requests": {"cpu": "250m"}}
            calico.setdefault("typha", {})["resources"] = {}
            calico.setdefault("kube-controllers", {})["resources"] = {}


class PluginsResourcesPatch(InventoryOnlyPatch):
    def __init__(self):
        super().__init__("plugins_resources")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Update user inventory to keep backward-compatible resources requests/limits for plugins
            """.rstrip()
        )