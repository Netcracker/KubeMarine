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

from kubemarine.core import utils


def _load_globals() -> dict:
    globals = utils.load_yaml(
        utils.get_internal_resource_path('resources/configurations/globals.yaml'))

    for config_filename in ('kubernetes_images.yaml', 'packages.yaml', 'plugins.yaml', 'thirdparties.yaml'):
        internal_compatibility = utils.load_yaml(
            utils.get_internal_resource_path(f'resources/configurations/compatibility/internal/{config_filename}'))

        globals_compatibility = globals['compatibility_map']['software']
        duplicates = set(internal_compatibility) & set(globals_compatibility)
        if duplicates:
            raise Exception(f"Duplicated software {', '.join(repr(s) for s in duplicates)}")

        globals_compatibility.update(internal_compatibility)

    return globals


def _load_supported_versions() -> dict:
    kubernetes_versions = utils.load_yaml(
        utils.get_internal_resource_path('resources/configurations/compatibility/kubernetes_versions.yaml'))

    return kubernetes_versions['kubernetes_versions']


GLOBALS = _load_globals()

DEFAULTS = utils.load_yaml(
    utils.get_internal_resource_path('resources/configurations/defaults.yaml'))

SUPPORTED_VERSIONS = _load_supported_versions()
