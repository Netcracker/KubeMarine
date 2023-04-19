from typing import Dict, List, Tuple, Optional

from ordered_set import OrderedSet

from kubemarine.core import static, utils
from .shell import info


class ChangesTracker:
    def __init__(self, kubernetes_versions: dict):
        self.kubernetes_versions = kubernetes_versions
        self.new_k8s: OrderedSet[str] = OrderedSet()
        self.deleted_k8s: OrderedSet[str] = OrderedSet()
        self.updated_k8s: Dict[str, OrderedSet[str]] = {}
        self.final_messages: List[str] = []
        self.unexpected_content = False

    @property
    def all_k8s_versions(self) -> List[str]:
        return list(self.kubernetes_versions)

    def new(self, k8s_version: str):
        self.new_k8s.add(k8s_version)
        self.updated_k8s.pop(k8s_version, None)

    def delete(self, k8s_version: str):
        self.deleted_k8s.add(k8s_version)

    def update(self, k8s_version: str, software_name: str):
        if k8s_version not in self.new_k8s:
            self.updated_k8s.setdefault(k8s_version, OrderedSet()).add(software_name)

    def is_software_changed(self, k8s_version: str, software_name: str) -> bool:
        return k8s_version in self.new_k8s or software_name in self.updated_k8s.get(k8s_version, set())

    def final_message(self, msg):
        self.final_messages.append(msg)

    def print(self):
        if self.new_k8s:
            info(f"New Kubernetes versions: {', '.join(self.new_k8s)}")
        if self.deleted_k8s:
            info(f"Deleted Kubernetes versions: {', '.join(self.deleted_k8s)}")
        if self.updated_k8s:
            info("Updated Kubernetes compatibility mapping:")
            for k8s_version, software_list in self.updated_k8s.items():
                info(f"\t{k8s_version}: {', '.join(software_list)}")

        self._print_software_requirements()

        if self.unexpected_content:
            info("Deleted unexpected content")

        if self.new_k8s or self.deleted_k8s or self.updated_k8s:
            info("Please do not forget to update documentation/Installation.md")
        elif not self.unexpected_content:
            info("Nothing has changed")

        for msg in self.final_messages:
            info(msg)

    def _print_software_requirements(self):
        software = dict(static.GLOBALS['plugins'])
        software.update(static.GLOBALS['software'])

        requirements: Dict[str, List[Tuple[str, str]]] = {}
        max_length = 0
        for k8s_version in self.all_k8s_versions:
            for software_name, settings_settings in software.items():
                related_software = [software_name]
                if software_name == 'containerd':
                    related_software.append('containerdio')

                if not any(self.is_software_changed(k8s_version, s) for s in related_software):
                    continue

                version = self.kubernetes_versions[k8s_version].get(software_name)
                req = self._get_software_requirements_link(settings_settings, version)
                max_length = max(max_length, len(software_name))
                requirements.setdefault(k8s_version, []).append((software_name, req))

        if not requirements:
            return

        info("Please check software compatibility and requirements.")

        for k8s_version, software_requirements in requirements.items():
            info(f"Kubernetes {k8s_version}:")
            for software_name, req in software_requirements:
                key = software_name + ': ' + (' ' * (max_length - len(software_name)))
                info(f"\t{key}{req}")

    def _get_software_requirements_link(self, settings_settings: dict, version: Optional[str]):
        minor_version = None if version is None else utils.minor_version(version)

        requirements = settings_settings['requirements']
        if version in requirements:
            req = requirements[version]
        elif minor_version in requirements:
            req = requirements[minor_version]
        else:
            req = requirements['default']

        return req.format(version=version, minor_version=minor_version)
