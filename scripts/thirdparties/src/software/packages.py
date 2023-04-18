from . import CompatibilityMap
from ..tracker import ChangesTracker


def sync(tracker: ChangesTracker):
    """
    Actualize compatibility_map of all packages.
    """
    package_names = ['docker', 'containerd', 'containerdio', 'podman',
                     'haproxy', 'keepalived']
    k8s_versions = tracker.all_k8s_versions

    compatibility_map = CompatibilityMap(tracker, "packages.yaml", package_names)
    for package_name in package_names:
        if package_name in ('haproxy', 'keepalived'):
            continue

        compatibility_map.prepare_software_mapping(package_name, k8s_versions)

        new_settings = {
            'version_rhel': '0.0.0',
            'version_rhel8': '0.0.0',
            'version_debian': '0.0.0',
        }
        if package_name == 'containerd':
            del new_settings['version_rhel']

        for k8s_version in k8s_versions:
            # Add fake versions only if mapping is absent
            compatibility_map.reset_software_settings(package_name, k8s_version,
                                                      dict(new_settings), update=False)

    compatibility_map.flush()
    if tracker.new_k8s:
        tracker.final_message(f"Please set required versions instead of 0.0.0 in {compatibility_map.resource}")
