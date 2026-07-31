# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
All files and directories inside kubemarine/patches directory should participate only in patching mechanism,
and relate to the current Kubemarine version.

The whole directory is automatically cleared and reset after new version of Kubemarine is released.
"""

from textwrap import dedent
from typing import List

from kubemarine.core.action import Action
from kubemarine.core.patch import Patch, RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.core import utils
from kubemarine.kubernetes import components, get_kubernetes_version

_NEW_ARG = "watch-progress-notify-interval"
_OLD_ARG = "experimental-watch-progress-notify-interval"
_RENAME_VERSION = "1.34"

class _EtcdReconfigurationAction(Action):
    def __init__(self) -> None:
        super().__init__("Add etcd watch-progress-notify-interval")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        kubernetes_version = get_kubernetes_version(cluster.inventory)

        if utils.version_key(kubernetes_version)[0:2] >= utils.minor_version_key(_RENAME_VERSION):
            target_arg = _NEW_ARG
            stale_arg = _OLD_ARG
        else:
            target_arg = _OLD_ARG
            stale_arg = _NEW_ARG

        def edit_etcd_args(cluster_config: dict) -> dict:
            # Get the config from the kubeadm-config ConfigMap.
            etcd_local: dict = (cluster_config
                                .setdefault("etcd", {})
                                .setdefault("local", {}))
            etcd_args = etcd_local.setdefault("extraArgs", [])
        
            existing_names = {entry["name"] for entry in etcd_args}
    
            # Check if the option must be set
            if _NEW_ARG not in existing_names and _OLD_ARG not in existing_names:
                etcd_local["extraArgs"] = [e for e in etcd_args if e["name"] != stale_arg]
                etcd_local["extraArgs"].append({"name": target_arg, "value": "5m"})
            else:
                cluster.log.info(
                    "etcd watch-progress-notify-interval is already configured on the cluster, skipping.")

            if "auto-compaction-mode" not in existing_names:
                etcd_local["extraArgs"].append({"name": "auto-compaction-mode", "value": "periodic"})
            else:
                cluster.log.info(
                    "etcd auto-compaction-mode is already configured on the cluster, skipping.")

            if "auto-compaction-retention" not in existing_names:
                etcd_local["extraArgs"].append({"name": "auto-compaction-retention", "value": "1h"})
            else:
                cluster.log.info(
                    "etcd auto-compaction-retention is already configured on the cluster, skipping.")

            if "snapshot-count" not in existing_names:
                etcd_local["extraArgs"].append({"name": "snapshot-count", "value": "100000"})
            else:
                cluster.log.info(
                    "etcd snapshot-count is already configured on the cluster, skipping.")

            return cluster_config

        control_plane = cluster.nodes['control-plane']
        control_plane.call(
            components.reconfigure_components,
            components=['etcd'],
            edit_functions={'kubeadm-config': edit_etcd_args},
        )


class EtcdReconfigurationPatch(RegularPatch):
    def __init__(self) -> None:
        super().__init__("etcd_reconfiguration")

    @property
    def action(self) -> Action:
        return _EtcdReconfigurationAction()

    @property
    def description(self) -> str:
        return dedent("""\
            Add watch-progress-notify-interval (or its experimental predecessor) to etcd extraArgs.
            For Kubernetes >= 1.34: sets --watch-progress-notify-interval=5m
            For Kubernetes <= 1.33: sets --experimental-watch-progress-notify-interval=5m
            Skipped if either arg is already explicitly set in the inventory.
            """.rstrip())

patches: List[Patch] = [
    EtcdReconfigurationPatch(),
]
"""
List of patches that is sorted according to the Patch.priority() before execution.
Patches that have the same priority, are executed in the declared order.
"""
