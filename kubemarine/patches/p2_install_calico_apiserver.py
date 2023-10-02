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

from kubemarine import plugins
from kubemarine.core.action import Action
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.plugins import builtin, manifest, calico


class TheAction(Action):
    def __init__(self) -> None:
        super().__init__("Install Calico API server")

    def run(self, res: DynamicResources) -> None:
        logger = res.logger()
        cluster = res.cluster()

        apiserver_manifest = manifest.Identity('calico', 'apiserver')
        if builtin.get_manifest_installation_step(cluster.inventory, apiserver_manifest) is None:
            return logger.info("Calico API server manifest is not configured. Skipping.")

        if res.raw_inventory().get('plugins', {}).get('calico', {}).get('installation', {}).get('procedures') is None:
            logger.debug("Custom installation steps are not configured. Install the API server only.")
            builtin.apply_yaml(cluster, 'calico', 'apiserver')
            calico.renew_apiserver_certificate(cluster)
            plugins.expect_deployment(cluster, [{'name': 'calico-apiserver', 'namespace': 'calico-apiserver'}])
            plugins.expect_pods(cluster, ['calico-apiserver'], namespace='calico-apiserver')
            # calico.expect_apiserver(cluster)
        else:
            logger.debug("The provided inventory has custom installation steps configured. "
                         "Need to re-install the whole Calico plugin.")
            plugins.install(cluster, {'calico': cluster.inventory['plugins']['calico']})


class InstallCalicoAPIServer(RegularPatch):
    def __init__(self) -> None:
        super().__init__("install_calico_apiserver")

    @property
    def action(self) -> Action:
        return TheAction()

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            The patch installs the Calico API server.
            """.rstrip()
        )
