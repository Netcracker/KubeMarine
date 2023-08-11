# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from textwrap import dedent

from kubemarine.core.action import Action
from kubemarine.core.patch import InventoryOnlyPatch
from kubemarine.core.resources import DynamicResources


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Update user inventory to keep backward-compatible resources requests/limits for plugins")

    def run(self, res: DynamicResources) -> None:
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
    def __init__(self) -> None:
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