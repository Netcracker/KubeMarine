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
import os
import uuid
import re
from typing import Dict, Any, List, Optional, Union

import ruamel.yaml
import yaml
from jinja2 import Template

from kubemarine import kubernetes
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, RunnersGroupResult
from kubemarine.core.yaml_merger import default_merger
from kubemarine.kubernetes import components
from kubemarine.plugins import builtin

privileged_policy_filename = "privileged.yaml"
policies_file_path = "./resources/psp/"
tmp_filepath_pattern = "/tmp/%s"

admission_template = "./templates/admission.yaml.j2"
admission_dir = "/etc/kubernetes/pki"
admission_path = "%s/admission.yaml" % admission_dir

psp_list_option = "psp-list"
roles_list_option = "roles-list"
bindings_list_option = "bindings-list"

provided_oob_policies = ["default", "host-network", "anyuid"]

valid_modes = ['enforce', 'audit', 'warn']
valid_versions_templ = r"^v1\.\d{1,2}$"

loaded_oob_policies = {}

# TODO: When KubeMarine is not support Kubernetes version lower than 1.25, the PSP implementation code should be deleted 


def support_pss_only(cluster: KubernetesCluster) -> bool:
    return components.kubernetes_minor_release_at_least(cluster.inventory, "v1.25")


def is_pod_security_unconditional(cluster: KubernetesCluster) -> bool:
    return components.kubernetes_minor_release_at_least(cluster.inventory, "v1.28")


def enrich_inventory_psp(inventory: dict, _: KubernetesCluster) -> dict:
    global loaded_oob_policies
    loaded_oob_policies = load_oob_policies_files()

    # validate custom
    custom_policies = inventory["rbac"]["psp"]["custom-policies"]
    verify_custom(custom_policies)

    # do not perform enrichment if security disabled
    if not is_security_enabled(inventory):
        return inventory

    # if security enabled, then add PodSecurityPolicy admission plugin
    enabled_admissions = inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["enable-admission-plugins"]
    if 'PodSecurityPolicy' not in enabled_admissions:
        enabled_admissions = "%s,PodSecurityPolicy" % enabled_admissions
        inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["enable-admission-plugins"] = enabled_admissions
        
    return inventory


def enrich_inventory_pss(inventory: dict, cluster: KubernetesCluster) -> dict:
    if not is_security_enabled(inventory):
        return inventory
    # check flags, enforce and logs parameters
    kubernetes_version = inventory["services"]["kubeadm"]["kubernetesVersion"]
    for item in inventory["rbac"]["pss"]["defaults"]:
        if item.endswith("version"):
            verify_version(item, inventory["rbac"]["pss"]["defaults"][item], kubernetes_version)

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

    return inventory


def enrich_inventory(inventory: dict, _: KubernetesCluster) -> dict:
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return enrich_inventory_psp(inventory, _)
    elif admission_impl == "pss":
        return enrich_inventory_pss(inventory, _)

    return inventory


def manage_psp_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    if support_pss_only(cluster):
        raise Exception("PSP is not supported in Kubernetes v1.25 or higher")
    if cluster.context.get('initial_procedure') != 'manage_psp':
        return inventory

    procedure_config = cluster.procedure_inventory["psp"]
    current_config = cluster.inventory["rbac"]["psp"]

    # validate added custom
    custom_add_policies = procedure_config.get("add-policies", {})
    verify_custom(custom_add_policies)

    # validate deleted custom
    custom_delete_policies = procedure_config.get("delete-policies", {})
    verify_custom(custom_delete_policies)

    # forbid managing OOB if security will be disabled
    current_security_state = current_config["pod-security"]
    final_security_state = procedure_config.get("pod-security", current_security_state)
    if final_security_state == "disabled" and procedure_config.get("oob-policies"):
        raise Exception("OOB policies can not be configured when security is disabled")

    cluster.context['initial_pod_security'] = current_security_state
    current_config["pod-security"] = final_security_state

    return inventory


def verify_custom(custom_scope: Dict[str, List[dict]]) -> None:
    psp_list = custom_scope.get(psp_list_option, None)
    if psp_list:
        verify_custom_list(psp_list, "PSP")

    roles_list = custom_scope.get(roles_list_option, None)
    if roles_list:
        verify_custom_list(roles_list, "role")

    bindings_list = custom_scope.get(bindings_list_option, None)
    if bindings_list:
        verify_custom_list(bindings_list, "binding")


def verify_custom_list(custom_list: List[dict], type: str) -> None:
    for item in custom_list:
        # forbid using 'oob-' prefix in order to avoid conflicts of our policies and users policies
        if item["metadata"]["name"].startswith("oob-"):
            raise Exception("Name %s is not allowed for custom %s" % (item["metadata"]["name"], type))


def verify_version(owner: str, version: str, kubernetes_version: str) -> None:
    # check Kubernetes version and admission config matching
    if version != "latest":
        result = re.match(valid_versions_templ, version)
        if result is None:
            raise Exception("incorrect Kubernetes version %s, valid version(for example): v1.23" % owner)
        if utils.minor_version_key(version) > utils.version_key(kubernetes_version)[0:2]:
            raise Exception("%s version must not be higher than Kubernetes version" % owner)


def finalize_inventory_psp(cluster: KubernetesCluster, inventory_to_finalize: dict,
                           procedure_inventory_for_finalization: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_psp':
        return inventory_to_finalize
    procedure_config = procedure_inventory_for_finalization["psp"]

    if "rbac" not in inventory_to_finalize:
        inventory_to_finalize["rbac"] = {}
    if "psp" not in inventory_to_finalize["rbac"]:
        inventory_to_finalize["rbac"]["psp"] = {}
    current_config = inventory_to_finalize["rbac"]["psp"]

    # Perform custom-policies lists changes.
    # Perform changes only if there are any "custom-policies" or "add-policies" in inventory,
    # do not perform changes if only "delete-policies" defined, there is nothing to delete from inventory in this case.
    adding_custom_policies = procedure_config.get("add-policies", {})
    deleting_custom_policies = procedure_config.get("delete-policies", {})
    existing_custom_policies = current_config.get("custom-policies", {})
    if existing_custom_policies or adding_custom_policies:
        # if custom policies are not defined in inventory, then we need to create custom policies ourselves
        if not existing_custom_policies:
            current_config["custom-policies"] = {}
        current_config["custom-policies"] = merge_custom_policies(existing_custom_policies,
                                                                  adding_custom_policies,
                                                                  deleting_custom_policies)

    # merge flags from procedure config and cluster config
    current_config["pod-security"] = procedure_config.get("pod-security", current_config.get("pod-security", "enabled"))
    if "oob-policies" in procedure_config:
        if "oob-policies" not in current_config:
            current_config["oob-policies"] = procedure_config["oob-policies"]
        else:
            for oob_policy in procedure_config["oob-policies"]:
                current_config["oob-policies"][oob_policy] = procedure_config["oob-policies"][oob_policy]

    return inventory_to_finalize


def merge_custom_policies(old_policies: Dict[str, List[dict]],
                          added_policies: Dict[str, List[dict]],
                          deleted_policies: Dict[str, List[dict]]) -> Dict[str, List[dict]]:
    return {
        psp_list_option: merge_policy_lists(old_policies.get(psp_list_option, []),
                                            added_policies.get(psp_list_option, []),
                                            deleted_policies.get(psp_list_option, [])),
        roles_list_option: merge_policy_lists(old_policies.get(roles_list_option, []),
                                              added_policies.get(roles_list_option, []),
                                              deleted_policies.get(roles_list_option, [])),
        bindings_list_option: merge_policy_lists(old_policies.get(bindings_list_option, []),
                                                 added_policies.get(bindings_list_option, []),
                                                 deleted_policies.get(bindings_list_option, []))
    }


def merge_policy_lists(old_list: List[dict], added_list: List[dict], deleted_list: List[dict]) -> List[dict]:
    resulting_list = added_list
    added_names_list = [item["metadata"]["name"] for item in added_list]
    deleted_names_list = [item["metadata"]["name"] for item in deleted_list]
    for old_item in old_list:
        old_item_name = old_item["metadata"]["name"]
        if old_item_name in added_names_list or old_item_name in deleted_names_list:
            # skip old item, since it was either deleted, replaced by new item, or deleted and then replaced
            continue
        # old item is nor deleted, nor updated, then we need to preserve it in resulting list
        resulting_list.append(old_item)

    return resulting_list


def install_psp_task(cluster: KubernetesCluster) -> None:
    if not is_security_enabled(cluster.inventory):
        cluster.log.debug("Pod security disabled, skipping policies installation...")
        return

    first_control_plane = cluster.nodes["control-plane"].get_first_member()

    cluster.log.debug("Installing OOB policies...")
    first_control_plane.call(manage_policies,
                      manage_type="apply",
                      manage_scope=resolve_oob_scope(cluster.inventory["rbac"]["psp"]["oob-policies"], "enabled"))

    cluster.log.debug("Installing custom policies...")
    first_control_plane.call(manage_policies,
                      manage_type="apply",
                      manage_scope=cluster.inventory["rbac"]["psp"]["custom-policies"])


def delete_custom_task(cluster: KubernetesCluster) -> None:
    if "delete-policies" not in cluster.procedure_inventory["psp"]:
        cluster.log.debug("No 'delete-policies' specified, skipping...")
        return

    cluster.log.debug("Deleting custom 'delete-policies'")
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    first_control_plane.call(manage_policies,
                      manage_type="delete",
                      manage_scope=cluster.procedure_inventory["psp"]["delete-policies"])


def add_custom_task(cluster: KubernetesCluster) -> None:
    if "add-policies" not in cluster.procedure_inventory["psp"]:
        cluster.log.debug("No 'add-policies' specified, skipping...")
        return

    cluster.log.debug("Applying custom 'add-policies'")
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    first_control_plane.call(manage_policies,
                      manage_type="apply",
                      manage_scope=cluster.procedure_inventory["psp"]["add-policies"])


def reconfigure_oob_task(cluster: KubernetesCluster) -> None:
    target_security_state = cluster.procedure_inventory["psp"].get("pod-security")
    oob_policies = cluster.procedure_inventory["psp"].get("oob-policies")

    # reconfigure OOB only if state will be changed, or OOB configuration was changed
    if not target_security_state and not oob_policies:
        cluster.log.debug("No need to reconfigure OOB policies, skipping...")
        return

    first_control_plane = cluster.nodes["control-plane"].get_first_member()

    cluster.log.debug("Deleting all OOB policies...")
    first_control_plane.call(delete_privileged_policy)
    first_control_plane.call(manage_policies, manage_type="delete", manage_scope=resolve_oob_scope(loaded_oob_policies, "all"))

    if target_security_state == "disabled":
        cluster.log.debug("Security disabled, OOB will not be recreated")
        return

    cluster.log.debug("Recreating all OOB policies...")
    policies_to_recreate = {}
    procedure_config = cluster.procedure_inventory["psp"].get("oob-policies", {})
    current_config = cluster.inventory["rbac"]["psp"]["oob-policies"]
    for policy in provided_oob_policies:
        if procedure_config.get(policy, current_config[policy]) == "enabled":
            policies_to_recreate[policy] = True
    first_control_plane.call(apply_privileged_policy)
    first_control_plane.call(manage_policies, manage_type="apply", manage_scope=resolve_oob_scope(policies_to_recreate, "all"))


def reconfigure_plugin_task(cluster: KubernetesCluster) -> None:
    target_state = cluster.procedure_inventory["psp"].get("pod-security")

    if not target_state:
        cluster.log.debug("Security plugin will not be reconfigured")
        return

    cluster.nodes['control-plane'].call(components.reconfigure_components, components=['kube-apiserver'])


def restart_pods_task(cluster: KubernetesCluster) -> None:
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
            hide=False)
        first_control_plane.sudo("kubectl uncordon %s" % node.get_node_name(), hide=False)

    cluster.log.debug("Restarting daemon-sets...")
    daemon_sets = ruamel.yaml.YAML().load(list(first_control_plane.sudo("kubectl get ds -A -o yaml").values())[0].stdout)
    for ds in daemon_sets["items"]:
        first_control_plane.sudo("kubectl rollout restart ds %s -n %s" % (ds["metadata"]["name"], ds["metadata"]["namespace"]))

    # we do not know to wait for, only for system pods maybe
    kube_nodes.call(components.wait_for_pods)


def is_security_enabled(inventory: dict) -> bool:
    admission_impl = inventory['rbac']['admission']
    target_state = "disabled"
    if admission_impl == "psp":
        target_state = inventory["rbac"]["psp"]["pod-security"]
    elif admission_impl == "pss":
        target_state = inventory["rbac"]["pss"]["pod-security"]

    return target_state == "enabled"


def apply_privileged_policy(group: NodeGroup) -> RunnersGroupResult:
    return manage_privileged_from_file(group, privileged_policy_filename, "apply")


def delete_privileged_policy(group: NodeGroup) -> RunnersGroupResult:
    return manage_privileged_from_file(group, privileged_policy_filename, "delete")


def apply_admission(group: NodeGroup) -> None:
    admission_impl = group.cluster.inventory['rbac']['admission']
    if admission_impl == "psp" and is_security_enabled(group.cluster.inventory):
        group.cluster.log.debug("Setting up privileged psp...")
        apply_privileged_policy(group)


def manage_privileged_from_file(group: NodeGroup, filename: str, manage_type: str) -> RunnersGroupResult:
    if manage_type not in ["apply", "delete"]:
        raise Exception("unexpected manage type for privileged policy")
    privileged_policy = utils.read_internal(os.path.join(policies_file_path, filename))
    remote_path = tmp_filepath_pattern % filename
    group.put(io.StringIO(privileged_policy), remote_path, backup=True, sudo=True)

    return group.sudo("kubectl %s -f %s" % (manage_type, remote_path), warn=True)


def resolve_oob_scope(oob_policies_conf: Dict[str, Any], selector: str) -> Dict[str, List[dict]]:
    result: Dict[str, List[dict]] = {
        psp_list_option: [],
        roles_list_option: [],
        bindings_list_option: []
    }

    for key, value in oob_policies_conf.items():
        if value == selector or selector == "all":
            policy = loaded_oob_policies[key]
            if "psp" in policy:
                result[psp_list_option].append(policy["psp"])
            if "role" in policy:
                result[roles_list_option].append(policy["role"])
            if "binding" in policy:
                result[bindings_list_option].append(policy["binding"])

    return result


def load_oob_policies_files() -> Dict[str, dict]:
    oob_policies = {}
    for oob_name in provided_oob_policies:
        local_path = os.path.join(policies_file_path, "%s.yaml" % oob_name)
        with utils.open_internal(local_path) as stream:
            oob_policies[oob_name] = yaml.safe_load(stream)

    return oob_policies


def manage_policies(group: NodeGroup, manage_type: str,
                    manage_scope: Dict[str, List[dict]]) -> Optional[RunnersGroupResult]:
    psp_to_manage = manage_scope.get(psp_list_option, None)
    roles_to_manage = manage_scope.get(roles_list_option, None)
    bindings_to_manage = manage_scope.get(bindings_list_option, None)

    if not psp_to_manage and not roles_to_manage and not bindings_to_manage:
        group.cluster.log.verbose("No policies to %s" % manage_type)
        return None

    template = collect_policies_template(psp_to_manage, roles_to_manage, bindings_to_manage)
    filename = uuid.uuid4().hex
    remote_path = tmp_filepath_pattern % filename
    group.put(io.StringIO(template), remote_path, backup=True, sudo=True)
    result = group.sudo("kubectl %s -f %s" % (manage_type, remote_path), warn=True)
    group.sudo("rm -f %s" % remote_path)
    return result


def collect_policies_template(psp_list: Optional[List[dict]],
                              roles_list: Optional[List[dict]],
                              bindings_list: Optional[List[dict]]) -> str:
    yaml = ruamel.yaml.YAML()

    buf = io.StringIO()
    if psp_list:
        for psp in psp_list:
            yaml.dump(psp, buf)
            buf.write("\n---\n")
    if roles_list:
        for role in roles_list:
            yaml.dump(role, buf)
            buf.write("\n---\n")
    if bindings_list:
        for binding in bindings_list:
            yaml.dump(binding, buf)
            buf.write("\n---\n")
    return buf.getvalue()


def install(cluster: KubernetesCluster) -> None:
    admission_impl = cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        install_psp_task(cluster)


def manage_pss_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory

    procedure_config = cluster.procedure_inventory["pss"]
    kubernetes_version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]

    if not is_security_enabled(inventory) and procedure_config["pod-security"] == "disabled":
        raise Exception("both 'pod-security' in procedure config and current config are 'disabled'. There is nothing to change")

    # check flags, profiles; enrich inventory
    cluster.context['initial_pod_security'] = inventory["rbac"]["pss"]["pod-security"]
    inventory["rbac"]["pss"]["pod-security"] = procedure_config["pod-security"]

    if "defaults" in procedure_config:
        for item in procedure_config["defaults"]:
            if item.endswith("version"):
                verify_version(item, procedure_config["defaults"][item], kubernetes_version)
            inventory["rbac"]["pss"]["defaults"][item] = procedure_config["defaults"][item]
    if "exemptions" in procedure_config:
        default_merger.merge(inventory["rbac"]["pss"]["exemptions"], procedure_config["exemptions"])
    if "namespaces" in procedure_config:
        for namespace_item in procedure_config["namespaces"]:
            # check if the namespace has its own profiles
            if isinstance(namespace_item, dict):
                namespace = list(namespace_item.keys())[0]
                for item in list(namespace_item[namespace]):
                    if namespace_item[namespace][item]:
                        if item.endswith("version"):
                            verify_version(item, namespace_item[namespace][item], kubernetes_version)
    if "namespaces_defaults" in procedure_config:
        for item in procedure_config["namespaces_defaults"]:
            if item.endswith("version"):
                verify_version(item, procedure_config["namespaces_defaults"][item], kubernetes_version)

    return inventory


def enrich_default_admission(inventory: dict, cluster: KubernetesCluster) -> dict:
    if not inventory["rbac"].get("admission"):
        inventory["rbac"]["admission"] = "psp" if not support_pss_only(cluster) else "pss"
    return inventory


def manage_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    check_inventory(cluster)
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return manage_psp_enrichment(inventory, cluster)
    elif admission_impl == "pss":
        return manage_pss_enrichment(inventory, cluster)

    return inventory


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
    control_planes.call(kubernetes.components.reconfigure_components,
                        components=['kube-apiserver'], force_restart=force_restart)

    if target_state == 'disabled':
        # erase PSS admission config
        cluster.log.debug("Erase admission configuration... %s" % admission_path)
        control_planes.sudo("rm -f %s" % admission_path, warn=True)


def finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict,
                       procedure_inventory_for_finalization: dict) -> dict:
    admission_impl = cluster.inventory['rbac']['admission']

    if admission_impl == "psp":
        return finalize_inventory_psp(cluster, inventory_to_finalize, procedure_inventory_for_finalization)
    elif admission_impl == "pss":
        return finalize_inventory_pss(cluster, inventory_to_finalize, procedure_inventory_for_finalization)

    return inventory_to_finalize


def finalize_inventory_pss(cluster: KubernetesCluster, inventory_to_finalize: dict,
                           procedure_inventory_for_finalization: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory_to_finalize
    procedure_config = procedure_inventory_for_finalization["pss"]

    current_config = inventory_to_finalize.setdefault("rbac", {}).setdefault("pss", {})

    # merge flags from procedure config and cluster config
    current_config["pod-security"] = procedure_config.get("pod-security", current_config.get("pod-security", "enabled"))
    if "defaults" in procedure_config:
        default_merger.merge(current_config.setdefault("defaults", {}), procedure_config["defaults"])
    if "exemptions" in procedure_config:
        default_merger.merge(current_config.setdefault("exemptions", {}), procedure_config["exemptions"])

    return inventory_to_finalize


# update PSP/PSS fields in the inventory dumped to cluster_finalized.yaml
def update_finalized_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    # remove PSP section from cluster_finalyzed.yaml
    if support_pss_only(cluster):
        del inventory_to_finalize["rbac"]["psp"]

    return inventory_to_finalize


def copy_pss(group: NodeGroup) -> Optional[RunnersGroupResult]:
    if group.cluster.inventory['rbac']['admission'] != "pss":
        return None

    if not is_security_enabled(group.cluster.inventory):
        group.cluster.log.debug("Pod security disabled, skipping pod admission installation...")
        return None

    defaults = group.cluster.inventory["rbac"]["pss"]["defaults"]
    exemptions = group.cluster.inventory["rbac"]["pss"]["exemptions"]
    # create admission config from template and cluster.yaml
    admission_config = Template(utils.read_internal(admission_template))\
                       .render(defaults=defaults,exemptions=exemptions)

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
                    for mode in default_modes:
                        first_control_plane.sudo(f"kubectl label ns {ns_name} "
                                f"pod-security.kubernetes.io/{mode}={default_modes[mode]} --overwrite")
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


def check_inventory(cluster: KubernetesCluster) -> None:
    # check if 'admission' option in cluster.yaml and procedure.yaml are inconsistent 
    if cluster.context.get('initial_procedure') == 'manage_pss' and cluster.inventory["rbac"]["admission"] != "pss" or \
        cluster.context.get('initial_procedure') == 'manage_psp' and cluster.inventory["rbac"]["admission"] != "psp":
        raise Exception("Procedure config and cluster config are inconsistent. Please check 'admission' option")
