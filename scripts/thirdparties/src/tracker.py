from typing import Dict

from ordered_set import OrderedSet
from .shell import info


class ChangesTracker:
    def __init__(self):
        self.new_k8s: OrderedSet[str] = OrderedSet()
        self.deleted_k8s: OrderedSet[str] = OrderedSet()
        self.updated_k8s: Dict[str, OrderedSet[str]] = {}
        self.unexpected_content = False

    def new(self, k8s_version: str):
        self.new_k8s.add(k8s_version)
        self.updated_k8s.pop(k8s_version, None)

    def delete(self, k8s_version: str):
        self.deleted_k8s.add(k8s_version)

    def update(self, k8s_version: str, software_name: str):
        if k8s_version not in self.new_k8s:
            self.updated_k8s.setdefault(k8s_version, OrderedSet()).add(software_name)

    def print(self):
        if self.new_k8s:
            info(f"New Kubernetes versions: {', '.join(self.new_k8s)}")
        if self.deleted_k8s:
            info(f"Deleted Kubernetes versions: {', '.join(self.deleted_k8s)}")
        if self.updated_k8s:
            info("Updated Kubernetes compatibility mapping:")
            for k8s_version, software_list in self.updated_k8s.items():
                info(f"\t{k8s_version}: {', '.join(software_list)}")

        if self.new_k8s or self.deleted_k8s or self.updated_k8s:
            info("Please do not forget to update documentation/Installation.md")
        elif self.unexpected_content:
            info("Deleted unexpected content")
        else:
            info("Nothing has changed")
