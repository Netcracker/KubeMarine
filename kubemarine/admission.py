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

import io
import re
from typing import Dict, List, Optional, Union

import ruamel.yaml
from jinja2 import Template

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup, RunnersGroupResult
from kubemarine.core.yaml_merger import default_merger
from kubemarine.kubernetes import components
from kubemarine.plugins import builtin

admission_template = "./templates/admission.yaml.j2"
admission_dir = "/etc/kubernetes/pki"
admission_path = "%s/admission.yaml" % admission_dir

valid_modes = ['enforce', 'audit', 'warn']
valid_versions_templ = r"^v1\.\d{1,2}$"

ERROR_PSS_BOTH_STATES_DISABLED = ("both 'pod-security' in procedure config and current config are 'disabled'. "
                                  "There is nothing to change")


def is_pod_security_unconditional(cluster: KubernetesCluster) -> bool:
    return components.kubernetes_minor_release_at_least(cluster.inventory, "v1.28")


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    # check flags, enforce and logs parameters
    kubernetes_version = inventory["services"]["kubeadm"]["kubernetesVersion"]

    for item, state in cluster.inventory["rbac"]["pss"]["defaults"].items():
        if item.endswith("version"):
            verify_version(item, state, kubernetes_version)

    if not is_security_enabled(inventory):
        return

    # add extraArgs to kube-apiserver config
    extra_args = inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]
    if not is_pod_security_unconditional(cluster):
        enabled_admissions = extra_args.get("feature-gates")
        if enabled_admissions:
            if 'PodSecurity=true' not in enabled_admissions:
                enabled_admissions = "%s,PodSecurity=true" % enabled_admissions
        else:
            enabled_admissions = "PodSecurity=true"

        extra_args["feature-gates"] = enabled_admissions

    extra_args["admission-control-config-file"] = admission_path


def verify_version(owner: str, version: str, kubernetes_version: str) -> None:
    # check Kubernetes version and admission config matching
    if version != "latest":
        result = re.match(valid_versions_templ, version)
        if result is None:
            raise Exception(f"Incorrect {owner} {version!r}, "
                            f"valid version (for example): {utils.minor_version(kubernetes_version)}")
        if utils.minor_version_key(version) > utils.version_key(kubernetes_version)[0:2]:
            raise Exception(f"{owner} must not be higher than Kubernetes version")


def restart_pods_task(cluster: KubernetesCluster) -> None:
    from kubemarine import kubernetes  # pylint: disable=cyclic-import

    if cluster.context.get('initial_procedure') == 'manage_pss':
        # check if pods restart is enabled
        is_restart = cluster.procedure_inventory.get("restart-pods", False)
        if not is_restart:
            cluster.log.debug("'restart-pods' is disabled, pods won't be restarted")
            return

    first_control_plane = cluster.nodes["control-plane"].get_first_member()

    cluster.log.debug("Drain-Uncordon all nodes to restart pods")
    kube_nodes = cluster.nodes["control-plane"].include_group(cluster.nodes["worker"])
    for node in kube_nodes.get_ordered_members_list():
        first_control_plane.sudo(
            kubernetes.prepare_drain_command(cluster, node.get_node_name(), disable_eviction=False),
            hide=False, pty=True)
        first_control_plane.sudo("kubectl uncordon %s" % node.get_node_name(), hide=False)

    cluster.log.debug("Restarting daemon-sets...")
    daemon_sets = ruamel.yaml.YAML().load(list(first_control_plane.sudo("kubectl get ds -A -o yaml").values())[0].stdout)
    for ds in daemon_sets["items"]:
        first_control_plane.sudo("kubectl rollout restart ds %s -n %s" % (ds["metadata"]["name"], ds["metadata"]["namespace"]))

    # we do not know to wait for, only for system pods maybe
    kube_nodes.call(components.wait_for_pods)


def is_security_enabled(inventory: dict) -> bool:
    target_state: str = inventory["rbac"]["pss"]["pod-security"]
    return target_state == "enabled"


@enrichment(EnrichmentStage.PROCEDURE, procedures=['manage_pss'])
def verify_manage_enrichment(cluster: KubernetesCluster) -> None:
    procedure_config = cluster.procedure_inventory["pss"]
    kubernetes_version = cluster.previous_inventory["services"]["kubeadm"]["kubernetesVersion"]

    if (cluster.previous_inventory["rbac"]["pss"]["pod-security"] == "disabled"
            and cluster.inventory["rbac"]["pss"]["pod-security"] == "disabled"):
        raise Exception(ERROR_PSS_BOTH_STATES_DISABLED)

    if "namespaces" in procedure_config:
        for namespace_item in procedure_config["namespaces"]:
            # check if the namespace has its own profiles
            if isinstance(namespace_item, dict):
                profiles = list(namespace_item.values())[0]
                for item in profiles:
                    if item.endswith("version"):
                        verify_version(item, profiles[item], kubernetes_version)
    if "namespaces_defaults" in procedure_config:
        for item in procedure_config["namespaces_defaults"]:
            if item.endswith("version"):
                verify_version(item, procedure_config["namespaces_defaults"][item], kubernetes_version)


def manage_pss(cluster: KubernetesCluster) -> None:
    control_planes = cluster.nodes["control-plane"]

    target_state = cluster.inventory["rbac"]["pss"]["pod-security"]

    # set labels for predefined plugins namespaces and namespaces defined in procedure config
    label_namespace_pss(cluster)

    # copy admission config on control-planes
    copy_pss(control_planes)

    # Admission configuration may change.
    # Force kube-apiserver pod restart, then wait for API server to become available.
    force_restart = True

    # Extra args of API may change, need to reconfigure the API server.
    # See enrich_inventory_pss()
    control_planes.call(components.reconfigure_components,
                        components=['kube-apiserver'], force_restart=force_restart)

    if target_state == 'disabled':
        # erase PSS admission config
        cluster.log.debug("Erase admission configuration... %s" % admission_path)
        control_planes.sudo("rm -f %s" % admission_path, warn=True)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['manage_pss'])
def manage_enrichment(cluster: KubernetesCluster) -> None:
    procedure_config = cluster.procedure_inventory["pss"]

    current_config = cluster.inventory.setdefault("rbac", {}).setdefault("pss", {})

    # merge flags from procedure config and cluster config
    current_config["pod-security"] = procedure_config["pod-security"]
    if "defaults" in procedure_config:
        default_merger.merge(current_config.setdefault("defaults", {}), procedure_config["defaults"])
    if "exemptions" in procedure_config:
        default_merger.merge(current_config.setdefault("exemptions", {}), procedure_config["exemptions"])


def generate_pss(cluster: KubernetesCluster) -> str:
    defaults = cluster.inventory["rbac"]["pss"]["defaults"]
    exemptions = cluster.inventory["rbac"]["pss"]["exemptions"]
    return Template(utils.read_internal(admission_template))\
        .render(defaults=defaults, exemptions=exemptions)


def copy_pss(group: NodeGroup) -> Optional[RunnersGroupResult]:
    if not is_security_enabled(group.cluster.inventory):
        group.cluster.log.debug("Pod security disabled, skipping pod admission installation...")
        return None

    # create admission config from template and cluster.yaml
    admission_config = generate_pss(group.cluster)

    # put admission config on every control-planes
    group.cluster.log.debug(f"Copy admission config to {admission_path}")
    group.put(io.StringIO(admission_config), admission_path, backup=True, sudo=True, mkdir=True)

    return group.sudo(f'ls -la {admission_path}')


def _get_default_labels(profile: str) -> Dict[str, str]:
    return {f"pod-security.kubernetes.io/{k}": v
            for mode in valid_modes
            for k, v in ((mode, profile), (f'{mode}-version', 'latest'))}


def get_labels_to_ensure_profile(inventory: dict, profile: str) -> Dict[str, str]:
    enforce_profile: str = inventory['rbac']['pss']['defaults']['enforce']
    if (enforce_profile == 'restricted' and profile != 'restricted'
            or enforce_profile == 'baseline' and profile == 'privileged'):
        return _get_default_labels(profile)

    return {}


def label_namespace_pss(cluster: KubernetesCluster) -> None:
    security_enabled = is_security_enabled(cluster.inventory)
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    # set/delete labels on predifined plugins namsespaces
    for ns_name, profile in builtin.get_namespace_to_necessary_pss_profiles(cluster).items():
        target_labels = get_labels_to_ensure_profile(cluster.inventory, profile)
        if security_enabled and target_labels:
            cluster.log.debug(f"Set PSS labels for profile {profile} on namespace {ns_name}")
            command = "kubectl label ns {namespace} {lk}={lv} --overwrite"

        else:  # Pod Security is disabled or default labels are not necessary
            cluster.log.debug(f"Delete PSS labels from namespace {ns_name}")
            command = "kubectl label ns {namespace} {lk}- || true"
            target_labels = _get_default_labels(profile)

        for lk, lv in target_labels.items():
            first_control_plane.sudo(command.format(namespace=ns_name, lk=lk, lv=lv))

    procedure_config = cluster.procedure_inventory["pss"]
    namespaces: List[Union[str, Dict[str, dict]]] = procedure_config.get("namespaces")
    # get the list of namespaces that should be labeled then set/delete labels
    if namespaces:
        default_modes = {}
        # check if procedure config has default values for labels
        namespaces_defaults = procedure_config.get("namespaces_defaults")
        if namespaces_defaults:
            for default_mode in namespaces_defaults:
                default_modes[default_mode] = namespaces_defaults[default_mode]
        for namespace in namespaces:
            # define name of namespace
            if isinstance(namespace, dict):
                ns_name = list(namespace.keys())[0]
            else:
                ns_name = namespace
            if security_enabled:
                if default_modes:
                    # set labels that are set in default section
                    cluster.log.debug(f"Set PSS labels on {ns_name} namespace from defaults")
                    for mode, value in default_modes.items():
                        first_control_plane.sudo(f"kubectl label ns {ns_name} "
                                f"pod-security.kubernetes.io/{mode}={value} --overwrite")
                if isinstance(namespace, dict):
                    # set labels that are set in namespaces section
                    cluster.log.debug(f"Set PSS labels on {ns_name} namespace")
                    for item in list(namespace[ns_name]):
                        first_control_plane.sudo(f"kubectl label ns {ns_name} " 
                                    f"pod-security.kubernetes.io/{item}={namespace[ns_name][item]} --overwrite")
            else:
                # delete labels that are set in default section
                if default_modes:
                    cluster.log.debug(f"Delete PSS labels on {ns_name} namespace from defaults")
                    for mode in default_modes:
                        first_control_plane.sudo(f"kubectl label ns {ns_name} pod-security.kubernetes.io/{mode}-")
                # delete labels that are set in namespaces section
                cluster.log.debug(f"Delete PSS labels on {ns_name} namespace")
                if isinstance(namespace, dict):
                    for item in list(namespace[ns_name]):
                        first_control_plane.sudo(f"kubectl label ns {ns_name} "
                                    f"pod-security.kubernetes.io/{item}-")
