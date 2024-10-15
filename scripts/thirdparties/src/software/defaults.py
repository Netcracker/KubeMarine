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

from kubemarine.core import utils

# pylint: disable=bad-builtin

YAML = utils.yaml_structure_preserver()
RESOURCE_PATH = utils.get_internal_resource_path("resources/configurations/defaults.yaml")


class KubemarineDefaults:
    def __init__(self) -> None:
        with utils.open_internal(RESOURCE_PATH) as stream:
            self._defaults = YAML.load(stream)

    def default_version(self) -> str:
        return str(self._defaults['services']['kubeadm']['kubernetesVersion'])
