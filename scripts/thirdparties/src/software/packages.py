from kubemarine.core import utils
from . import SoftwareType, InternalCompatibility, CompatibilityMap
from ..tracker import ChangesTracker


class Packages(SoftwareType):
    def __init__(self, compatibility: InternalCompatibility):
        super().__init__(compatibility)

    def sync(self, tracker: ChangesTracker):
        """
        Actualize compatibility_map of all packages.
        """
        package_names = ['docker', 'containerd', 'containerdio', 'podman',
                         'haproxy', 'keepalived']
        k8s_versions = tracker.all_k8s_versions

        compatibility_map = self.compatibility.load(tracker, "packages.yaml", package_names)
        for package_name in package_names:
            if package_name in ('haproxy', 'keepalived'):
                continue

            compatibility_map.prepare_software_mapping(package_name, k8s_versions)

            for k8s_version in k8s_versions:
                new_settings = resolve_new_settings(compatibility_map, package_name, k8s_version)
                compatibility_map.reset_software_settings(package_name, k8s_version, new_settings)

        self.compatibility.store(compatibility_map)
        if tracker.new_k8s:
            tracker.final_message(f"Please check package versions in {compatibility_map.resource}")


def resolve_new_settings(compatibility_map: CompatibilityMap, package_name: str, k8s_version: str) -> dict:
    new_settings = {
        'version_rhel': '0.0.0',
        'version_rhel8': '0.0.0',
        'version_debian': '0.0.0',
    }
    if package_name == 'containerd':
        del new_settings['version_rhel']

    package_mapping = compatibility_map.compatibility_map[package_name]
    if k8s_version in package_mapping:
        package_settings = package_mapping[k8s_version]
    else:
        package_settings = new_settings
        key = utils.version_key
        prev_k8s_version = max((v for v in package_mapping if key(v) < key(k8s_version)),
                               default=None)
        if prev_k8s_version is not None:
            print(f"Mapping for package {package_name!r} and Kubernetes {k8s_version} does not exist. "
                  f"Taking from {prev_k8s_version}.")
            package_settings = package_mapping[prev_k8s_version]

    for k in new_settings.keys():
        if k in package_settings:
            new_settings[k] = package_settings[k]

    return new_settings
