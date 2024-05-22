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
from typing import cast, Optional

from kubemarine import plugins
from kubemarine.core import utils
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes import deployment
from kubemarine.plugins import builtin, manifest, calico


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Schedule Calico Typha on control-planes")

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        logger = cluster.log

        calico_version = cluster.inventory['plugins']['calico']['version']
        if utils.version_key(calico_version)[0:2] >= utils.minor_version_key("v3.27"):
            return logger.info("The patch is not relevant for Calico >= v3.27.x.")

        if not calico.is_typha_enabled(cluster.inventory):
            return logger.info("The patch is skipped as Calico Typha is not enabled.")

        processor = cast(Optional[calico.CalicoLess_3_27_ManifestProcessor],
                         builtin.get_manifest_processor(cluster, manifest.Identity('calico')))
        if processor is None:
            return logger.warning("Calico manifest is not installed using default procedure. The patch is skipped.")

        original_manifest = processor.original_manifest()
        if not processor.get_typha_schedule_control_plane_extra_tolerations(original_manifest):
            return logger.info("Necessary tolerations already exist in the original manifest. The patch is skipped.")

        manifest_ = processor.enrich()
        key = "Deployment_calico-typha"
        typha_deployment_yaml = manifest_.get_obj(key, patch=False)

        typha_deployment = deployment.Deployment(cluster, 'calico-typha', 'kube-system', typha_deployment_yaml)
        logger.debug("Apply patched 'calico-typha' deployment")
        typha_deployment.apply(cluster.nodes['control-plane'].get_first_member())

        logger.debug("Expect 'calico-typha' deployment and pods")
        plugins.expect_deployment(cluster, [{'name': 'calico-typha', 'namespace': 'kube-system'}])
        plugins.expect_pods(cluster, ['calico-typha'], namespace='kube-system')


class CalicoTyphaScheduleControlPlane(RegularPatch):
    def __init__(self) -> None:
        super().__init__("calico_typha_schedule_control_planes")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Allow to schedule Calico Typha pods on control-planes.
            
            This effectively resolves https://github.com/projectcalico/calico/pull/7979 in older versions.
            """.rstrip()
        )
