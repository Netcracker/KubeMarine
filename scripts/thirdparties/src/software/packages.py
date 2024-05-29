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
from copy import deepcopy
from typing import List

from kubemarine.core import utils
from . import SoftwareType, CompatibilityMap, UpgradeSoftware
from ..tracker import SummaryTracker, ComposedTracker

# pylint: disable=bad-builtin


class UpgradePackages(UpgradeSoftware):
    def prepare(self, summary_tracker: SummaryTracker) -> None:
        for software_name in self.software_names:
            if software_name not in self.config:
                self.config[software_name] = {}

        super().prepare(summary_tracker)

    def delete(self, k8s_version: str, software_name: str) -> None:
        if software_name not in self.software_names:
            return

        os_mapping: dict = self.config[software_name]
        for k8s_versions in os_mapping.values():
            if isinstance(k8s_versions, list) and k8s_version in k8s_versions:
                k8s_versions.remove(k8s_version)

    def update(self, k8s_version: str, software_name: str) -> None:
        # The management tool is not able to update packages compatibility map.
        return


class Packages(SoftwareType):
    @property
    def name(self) -> str:
        return 'packages'

    def sync(self, summary_tracker: SummaryTracker) -> CompatibilityMap:
        """
        Actualize compatibility_map of all packages.
        """
        package_names = ['containerd', 'containerdio', 'haproxy', 'keepalived']
        k8s_versions = summary_tracker.all_k8s_versions

        upgrade_packages = UpgradePackages(self.upgrade_config, self.name, package_names)
        upgrade_packages.prepare(summary_tracker)

        tracker = ComposedTracker(summary_tracker, upgrade_packages)
        compatibility_map = self.compatibility.load(tracker, "packages.yaml")
        compatibility_map.prepare(summary_tracker, package_names)

        for package_name in package_names:
            prepare_upgrade_config_stub(upgrade_packages, package_name)

            if package_name in ('haproxy', 'keepalived'):
                continue

            compatibility_map.prepare_software_mapping(package_name, k8s_versions)

            for k8s_version in k8s_versions:
                new_settings = resolve_new_settings(compatibility_map, package_name, k8s_version)
                compatibility_map.reset_software_settings(package_name, k8s_version, new_settings)

        if summary_tracker.new_k8s:
            summary_tracker.final_message(f"Please check package versions in {compatibility_map.resource}")

        return compatibility_map


def get_compatibility_version_keys(package_name: str) -> List[str]:
    keys = [
        'version_rhel',
        'version_rhel8',
        'version_rhel9',
        'version_debian',
    ]
    if package_name == 'containerd':
        keys.remove('version_rhel')
        keys.remove('version_rhel8')
        keys.remove('version_rhel9')
    elif package_name == 'containerdio':
        keys.remove('version_debian')

    return keys


def prepare_upgrade_config_stub(upgrade_software: UpgradePackages, package_name: str) -> None:
    stub = False if package_name in ('haproxy', 'keepalived') else []
    version_keys = get_compatibility_version_keys(package_name)

    os_mapping: dict = upgrade_software.config[package_name]

    for version_key in version_keys:
        if version_key not in os_mapping:
            os_mapping[version_key] = deepcopy(stub)

    map_keys = list(os_mapping)
    for key in map_keys:
        if key not in version_keys:
            del os_mapping[key]
            print(f"Deleted {upgrade_software.software_type}.{package_name}.{key} "
                  f"from {upgrade_software.upgrade_config.name}")


def resolve_new_settings(compatibility_map: CompatibilityMap, package_name: str, k8s_version: str) -> dict:
    new_settings = {key: '0.0.0' for key in get_compatibility_version_keys(package_name)}

    package_mapping = compatibility_map.compatibility_map[package_name]
    if k8s_version in package_mapping:
        package_settings = package_mapping[k8s_version]
    else:
        package_settings = new_settings
        key = utils.version_key
        prev_k8s_version = max((v for v in package_mapping if key(v) < key(k8s_version)),
                               key=key,
                               default=None)
        if prev_k8s_version is not None:
            print(f"Mapping for package {package_name!r} and Kubernetes {k8s_version} does not exist. "
                  f"Taking from {prev_k8s_version}.")
            package_settings = package_mapping[prev_k8s_version]

    for k in new_settings.keys():
        if k in package_settings:
            new_settings[k] = package_settings[k]

    return new_settings
