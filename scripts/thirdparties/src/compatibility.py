from copy import deepcopy

from ruamel.yaml import CommentedMap

from kubemarine.core import utils, static
from .shell import fatal, info, run

YAML = utils.yaml_structure_preserver()
RESOURCE_PATH = utils.get_internal_resource_path("resources/configurations/compatibility/kubernetes_versions.yaml")


class KubernetesVersions:
    def __init__(self):
        with utils.open_internal(RESOURCE_PATH) as stream:
            self._kubernetes_versions = YAML.load(stream)
            self._validate_mapping()

    @property
    def compatibility_map(self) -> dict:
        return deepcopy(self._kubernetes_versions['compatibility_map'])

    def sync(self):
        k8s_versions = self._kubernetes_versions['kubernetes_versions']
        k8s_versions = utils.map_sorted(k8s_versions, key=utils.version_key)
        self._kubernetes_versions['kubernetes_versions'] = k8s_versions

        minor_versions = set()
        for k8s_version in self._kubernetes_versions['compatibility_map']:
            minor_version = utils.minor_version(k8s_version)
            minor_versions.add(minor_version)
            if minor_version not in k8s_versions:
                utils.insert_map_sorted(k8s_versions, minor_version, CommentedMap({'supported': True}),
                                        key=utils.version_key)

        for key in list(k8s_versions):
            if key not in minor_versions:
                del k8s_versions[key]

        with utils.open_internal(RESOURCE_PATH, 'w') as stream:
            YAML.dump(self._kubernetes_versions, stream)

        run(['git', 'add', RESOURCE_PATH])
        info(f"Updated kubernetes_versions.yaml")

    def _validate_mapping(self):
        mandatory_fields = set(static.GLOBALS['plugins'])
        mandatory_fields.update(['crictl'])
        optional_fields = {'pause', 'webhook', 'metrics-scraper', 'busybox'}

        compatibility_map = self._kubernetes_versions['compatibility_map']
        for k8s_version, software in compatibility_map.items():
            missing_mandatory = mandatory_fields - set(software)
            if missing_mandatory:
                fatal(f"Missing {', '.join(repr(s) for s in missing_mandatory)} software "
                      f"for Kubernetes {k8s_version} in kubernetes_versions.yaml")

            unexpected_optional = set(software) - mandatory_fields - optional_fields
            if unexpected_optional:
                fatal(f"Unexpected {', '.join(repr(s) for s in unexpected_optional)} software "
                      f"for Kubernetes {k8s_version} in kubernetes_versions.yaml. "
                      f"Allowed optional software: {', '.join(repr(s) for s in optional_fields)}.")
