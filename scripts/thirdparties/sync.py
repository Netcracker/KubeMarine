import os
import sys

# Ensure to take Kubemarine modules from the project root.
# !!! This should be a very first line of the script !!!
ROOT = os.path.abspath(f"{__file__}/../../..")
sys.path.insert(0, ROOT)

import platform
import yaml

from kubemarine.core import utils
from src.tracker import ChangesTracker
from src.shell import fatal
from src.software import thirdparties


if platform.system() != 'Linux':
    fatal("The tool can be run only on Linux.")


def validate_mapping(kubernetes_versions: dict):
    mandatory_fields = {'calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner',
                        'crictl'}
    optional_fields = {'pause'}

    for k8s_version, software in kubernetes_versions.items():
        missing_mandatory = mandatory_fields - set(software)
        if missing_mandatory:
            fatal(f"Missing {', '.join(repr(s) for s in missing_mandatory)} software "
                  f"for Kubernetes {k8s_version} in kubernetes_versions.yaml")

        unexpected_optional = set(software) - mandatory_fields - optional_fields
        if unexpected_optional:
            fatal(f"Unexpected {', '.join(repr(s) for s in unexpected_optional)} software "
                  f"for Kubernetes {k8s_version} in kubernetes_versions.yaml")


with utils.open_internal("resources/configurations/compatibility/kubernetes_versions.yaml") as stream:
    kubernetes_versions = yaml.safe_load(stream)
    validate_mapping(kubernetes_versions)

tracker = ChangesTracker()

thirdparties.sync(tracker, kubernetes_versions)

tracker.print()
