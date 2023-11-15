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


def enrich_inventory_pss(inventory: dict, _: KubernetesCluster) -> dict:
    if not is_security_enabled(inventory):
        return inventory
    # check flags, enforce and logs parameters
    minor_version = int(inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
    if minor_version < 23:
        raise Exception("PSS is not supported properly in Kubernetes version before v1.23")
    for item in inventory["rbac"]["pss"]["defaults"]:
        if item.endswith("version"):
            verify_version(item, inventory["rbac"]["pss"]["defaults"][item], minor_version)

    # add extraArgs to kube-apiserver config
    extra_args = inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]
    if minor_version <= 27:
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
    minor_version = int(inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
    if minor_version >= 25:
        raise Exception("PSP is not supported in Kubernetes version higher than v1.24")
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


def verify_version(owner: str, version: str, minor_version_cfg: int) -> None:
    # check Kubernetes version and admission config matching
    if version != "latest":
        result = re.match(valid_versions_templ, version)
        if result is None:
            raise Exception("incorrect Kubernetes version %s, valid version(for example): v1.23" % owner)
        minor_version = int(version.split('.')[1])
        if minor_version > minor_version_cfg:
            raise Exception("%s version must not be higher than Kubernetes version" % owner)


def finalize_inventory_psp(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_psp':
        return inventory_to_finalize
    procedure_config = cluster.procedure_inventory["psp"]

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

    first_control_plane = cluster.nodes["control-plane"].get_first_member()

    cluster.log.debug("Updating kubeadm config map")
    final_admission_plugins_list = first_control_plane.call(update_kubeadm_configmap, target_state=target_state)

    # update api-server config on all control-planes
    cluster.log.debug("Updating kube-apiserver configs on control-planes")
    cluster.nodes["control-plane"].call(update_kubeapi_config, options_list=final_admission_plugins_list)


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
    cluster.log.debug("Waiting for system pods...")
    kubernetes.wait_for_any_pods(cluster, first_control_plane)


def update_kubeadm_configmap_psp(first_control_plane: NodeGroup, target_state: str) -> str:
    yaml = ruamel.yaml.YAML()

    # load kubeadm config map and retrieve cluster config
    result = first_control_plane.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
    kubeadm_cm = yaml.load(list(result.values())[0].stdout)
    cluster_config = yaml.load(kubeadm_cm["data"]["ClusterConfiguration"])

    # resolve resulting admission plugins list
    final_plugins_string = resolve_final_plugins_list(cluster_config, target_state)

    # update kubeadm config map with updated plugins list
    cluster_config["apiServer"]["extraArgs"]["enable-admission-plugins"] = final_plugins_string
    buf = io.StringIO()
    yaml.dump(cluster_config, buf)
    kubeadm_cm["data"]["ClusterConfiguration"] = buf.getvalue()

    # apply updated kubeadm config map
    buf = io.StringIO()
    yaml.dump(kubeadm_cm, buf)
    filename = uuid.uuid4().hex
    first_control_plane.put(buf, "/tmp/%s.yaml" % filename)
    first_control_plane.sudo("kubectl apply -f /tmp/%s.yaml" % filename)
    first_control_plane.sudo("rm -f /tmp/%s.yaml" % filename)

    return final_plugins_string


def update_kubeadm_configmap(first_control_plane: NodeGroup, target_state: str) -> str:
    admission_impl = first_control_plane.cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        return update_kubeadm_configmap_psp(first_control_plane, target_state)
    else:  # admission_impl == "pss":
        return update_kubeadm_configmap_pss(first_control_plane, target_state)


def update_kubeapi_config_psp(control_planes: NodeGroup, plugins_list: str) -> None:
    yaml = ruamel.yaml.YAML()

    for control_plane in control_planes.get_ordered_members_list():
        result = control_plane.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")

        # update kube-apiserver config with updated plugins list
        conf = yaml.load(list(result.values())[0].stdout)
        new_command = [cmd for cmd in conf["spec"]["containers"][0]["command"] if "enable-admission-plugins" not in cmd]
        new_command.append("--enable-admission-plugins=%s" % plugins_list)
        conf["spec"]["containers"][0]["command"] = new_command

        # place updated config on control-plane
        buf = io.StringIO()
        yaml.dump(conf, buf)
        control_plane.put(buf, "/etc/kubernetes/manifests/kube-apiserver.yaml", sudo=True)

    # force kube-apiserver pod restart, then wait for api to become available
        if control_planes.cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
            control_plane.call(utils.wait_command_successful,
                                                   command="crictl rm -f $(sudo crictl ps --name kube-apiserver -q)")
        else:
            control_plane.call(utils.wait_command_successful,
                                                   command="docker stop $(sudo docker ps -q -f 'name=k8s_kube-apiserver'"
                                                           " | awk '{print $1}')")
        control_plane.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")


def update_kubeapi_config(control_planes: NodeGroup, options_list: str) -> None:
    admission_impl = control_planes.cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        update_kubeapi_config_psp(control_planes, options_list)
    elif admission_impl == "pss":
        update_kubeapi_config_pss(control_planes, options_list)


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
    if is_security_enabled(group.cluster.inventory):
        if admission_impl == "psp":
            group.cluster.log.debug("Setting up privileged psp...")
            apply_privileged_policy(group)
        elif admission_impl == "pss":
            group.cluster.log.debug("Setting up default pss...")
            apply_default_pss(group.cluster)


def apply_default_pss(cluster: KubernetesCluster) -> None:
    if cluster.context.get('initial_procedure') == 'manage_pss':
        procedure_config = cluster.procedure_inventory["pss"]
        current_config = cluster.inventory["rbac"]["pss"]
        if procedure_config["pod-security"] == "enabled" and current_config["pod-security"] == "enabled":
            manage_pss(cluster, "apply")
        elif procedure_config["pod-security"] == "enabled" and current_config["pod-security"] == "disabled":
            manage_pss(cluster, "install")
    else:
        manage_pss(cluster, "init")


def delete_default_pss(cluster: KubernetesCluster) -> None:
    procedure_config = cluster.procedure_inventory["pss"]
    current_config = cluster.inventory["rbac"]["pss"]
    if procedure_config["pod-security"] == "disabled" and current_config["pod-security"] == "enabled":
        return manage_pss(cluster, "delete")


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


def resolve_final_plugins_list(cluster_config: dict, target_state: str) -> str:
    if "enable-admission-plugins" not in cluster_config["apiServer"]["extraArgs"]:
        if target_state == "enabled":
            return "PodSecurityPolicy"
        else:
            return ""
    else:
        current_plugins = cluster_config["apiServer"]["extraArgs"]["enable-admission-plugins"]
        if "PodSecurityPolicy" not in current_plugins:
            if target_state == "enabled":
                resulting_list = "%s,%s" % (current_plugins, "PodSecurityPolicy")
            else:
                resulting_list = current_plugins
        elif target_state == "disabled":
            resulting_list = current_plugins.replace("PodSecurityPolicy", "")
        else:
            resulting_list = current_plugins

        return resulting_list.replace(",,", ",").strip(",")


def install(cluster: KubernetesCluster) -> None:
    admission_impl = cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        install_psp_task(cluster)


def manage_pss_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory

    procedure_config = cluster.procedure_inventory["pss"]
    minor_version = int(cluster.inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
        
    if not is_security_enabled(inventory) and procedure_config["pod-security"] == "disabled":
        raise Exception("both 'pod-security' in procedure config and current config are 'disabled'. There is nothing to change")

    # check flags, profiles; enrich inventory
    if minor_version < 23:
        raise Exception("PSS is not supported properly in Kubernetes version before v1.23")
    if "defaults" in procedure_config:
        for item in procedure_config["defaults"]:
            if item.endswith("version"):
                verify_version(item, procedure_config["defaults"][item], minor_version)
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
                            verify_version(item, namespace_item[namespace][item], minor_version)
    if "namespaces_defaults" in procedure_config:
        for item in procedure_config["namespaces_defaults"]:
            if item.endswith("version"):
                verify_version(item, procedure_config["namespaces_defaults"][item], minor_version)

    return inventory


def enrich_default_admission(inventory: dict, _: KubernetesCluster) -> dict:
    minor_version = int(inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
    if not inventory["rbac"].get("admission"):
        inventory["rbac"]["admission"] = "psp" if minor_version < 25 else "pss"
    return inventory


def manage_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return manage_psp_enrichment(inventory, cluster)
    elif admission_impl == "pss":
        return manage_pss_enrichment(inventory, cluster)

    return inventory


def manage_pss(cluster: KubernetesCluster, manage_type: str) -> None:
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    control_planes = cluster.nodes["control-plane"]
    # 'apply' - change options in admission.yaml, PSS is enabled
    if manage_type == "apply":
        # set labels for predifined plugins namespaces and namespaces defined in procedure config
        label_namespace_pss(cluster, manage_type)
        # copy admission config on control-planes
        copy_pss(control_planes)
        for control_plane in control_planes.get_ordered_members_list():
            # force kube-apiserver pod restart, then wait for api to become available
            if control_plane.cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
                control_plane.call(utils.wait_command_successful, command="crictl rm -f "
                                                       "$(sudo crictl ps --name kube-apiserver -q)")
            else:
                control_plane.call(utils.wait_command_successful, command="docker stop "
                                                       "$(sudo docker ps -f 'name=k8s_kube-apiserver'"
                                                       " | awk '{print $1}')")
            control_plane.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")
    # 'install' - enable PSS
    elif manage_type == "install":
        # set labels for predifined plugins namespaces and namespaces defined in procedure config
        label_namespace_pss(cluster, manage_type)
        # copy admission config on control-planes
        copy_pss(cluster.nodes["control-plane"])

        cluster.log.debug("Updating kubeadm config map")
        final_features_list = first_control_plane.call(update_kubeadm_configmap_pss, target_state="enabled")

        # update api-server config on all control-planes
        cluster.log.debug("Updating kube-apiserver configs on control-planes")
        cluster.nodes["control-plane"].call(update_kubeapi_config_pss, features_list=final_features_list)
    # 'init' make changes during init Kubernetes cluster
    elif manage_type == "init":
        cluster.log.debug("Updating kubeadm config map")
        first_control_plane.call(update_kubeadm_configmap_pss, target_state="enabled")
    # 'delete' - disable PSS
    elif manage_type == "delete":
        # set labels for predifined plugins namespaces and namespaces defined in procedure config
        label_namespace_pss(cluster, manage_type)

        final_features_list = first_control_plane.call(update_kubeadm_configmap, target_state="disabled")

        # update api-server config on all control-planes
        cluster.log.debug("Updating kube-apiserver configs on control-planes")
        cluster.nodes["control-plane"].call(update_kubeapi_config_pss, features_list=final_features_list)

        # erase PSS admission config 
        cluster.log.debug("Erase admission configuration... %s" % admission_path)
        group = cluster.nodes["control-plane"]
        group.sudo("rm -f %s" % admission_path, warn=True)


def update_kubeapi_config_pss(control_planes: NodeGroup, features_list: str) -> None:
    yaml = ruamel.yaml.YAML()

    for control_plane in control_planes.get_ordered_members_list():
        result = control_plane.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")
        if control_plane.cluster.context['initial_procedure'] == 'upgrade':
            minor_version = int(control_plane.cluster.context['upgrade_version'].split('.')[1])
        else:
            minor_version = int(control_plane.cluster.inventory['services']['kubeadm']['kubernetesVersion'].split('.')[1])
        # update kube-apiserver config with updated features list or delete '--feature-gates' and '--admission-control-config-file'
        conf = yaml.load(list(result.values())[0].stdout)
        new_command = [cmd for cmd in conf["spec"]["containers"][0]["command"]]
        if len(features_list) != 0:
            if minor_version <= 27:
                if 'PodSecurity=true' in features_list:
                    new_command.append("--admission-control-config-file=%s" % admission_path)
                else:
                    new_command.append("--admission-control-config-file=''")
                new_command.append("--feature-gates=%s" % features_list)
            else:
                new_command.append("--admission-control-config-file=%s" % admission_path)
                if control_plane.cluster.context['initial_procedure'] == 'upgrade':
                    if any(argument in "--feature-gates=PodSecurity=true" for argument in new_command):
                        new_command.remove("--feature-gates=PodSecurity=true")
        else:
            for item in conf["spec"]["containers"][0]["command"]:
                if item.startswith("--"):
                    key = item.split('=')[0]
                    value = item[len(key)+1:]
                    if key in ["--feature-gates", "--admission-control-config-file"]:
                        del_option = "%s=%s" % (key, value)
                        new_command.remove(del_option)

        conf["spec"]["containers"][0]["command"] = new_command

        # place updated config on control-plane
        buf = io.StringIO()
        yaml.dump(conf, buf)
        control_plane.put(buf, "/etc/kubernetes/manifests/kube-apiserver.yaml", sudo=True)

        # force kube-apiserver pod restart, then wait for api to become available
        if control_plane.cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
            control_plane.call(utils.wait_command_successful, command="crictl rm -f "
                                                       "$(sudo crictl ps --name kube-apiserver -q)")
        else:
            control_plane.call(utils.wait_command_successful, command="docker stop "
                                                       "$(sudo docker ps -f 'name=k8s_kube-apiserver'"
                                                       " | awk '{print $1}')")
        control_plane.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")


def update_kubeadm_configmap_pss(first_control_plane: NodeGroup, target_state: str) -> str:
    yaml = ruamel.yaml.YAML()

    final_feature_list = ""

    # load kubeadm config map and retrieve cluster config
    result = first_control_plane.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
    kubeadm_cm = yaml.load(list(result.values())[0].stdout)
    cluster_config = yaml.load(kubeadm_cm["data"]["ClusterConfiguration"])
    if first_control_plane.cluster.context['initial_procedure'] == 'upgrade':
        minor_version = int(first_control_plane.cluster.context['upgrade_version'].split('.')[1])
    else:
        minor_version = int(cluster_config['kubernetesVersion'].split('.')[1])

    # update kubeadm config map with feature list
    if target_state == "enabled":
        if minor_version <= 27:
            if "feature-gates" in cluster_config["apiServer"]["extraArgs"]:
                enabled_admissions = cluster_config["apiServer"]["extraArgs"]["feature-gates"]
                if 'PodSecurity=true' not in enabled_admissions:
                    enabled_admissions = "%s,PodSecurity=true" % enabled_admissions
                    cluster_config["apiServer"]["extraArgs"]["feature-gates"] = enabled_admissions
                    cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
                    final_feature_list = enabled_admissions
                else:
                    cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
                    final_feature_list = enabled_admissions
            else:
                cluster_config["apiServer"]["extraArgs"]["feature-gates"] = "PodSecurity=true"
                cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
                final_feature_list = "PodSecurity=true"
        else:
            cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
            if first_control_plane.cluster.context['initial_procedure'] == 'upgrade':
                if cluster_config["apiServer"]["extraArgs"].get("feature-gates"):
                    del cluster_config["apiServer"]["extraArgs"]["feature-gates"]
            final_feature_list = "PodSecurity deprecated in %s" % cluster_config['kubernetesVersion']
    elif target_state == "disabled":
        if minor_version <= 27:
            feature_list = cluster_config["apiServer"]["extraArgs"]["feature-gates"].replace("PodSecurity=true", "")
            final_feature_list = feature_list.replace(",,", ",")
            if len(final_feature_list) == 0:
                del cluster_config["apiServer"]["extraArgs"]["feature-gates"]
                del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]
            else:
                cluster_config["apiServer"]["extraArgs"]["feature-gates"] = final_feature_list
                del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]
        else:
            if cluster_config["apiServer"]["extraArgs"].get("feature-gates"):
                if len(cluster_config["apiServer"]["extraArgs"]["feature-gates"]) == 0:
                    del cluster_config["apiServer"]["extraArgs"]["feature-gates"]
                    del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]
                else:
                    del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]
            else:
                del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]

    buf = io.StringIO()
    yaml.dump(cluster_config, buf)
    kubeadm_cm["data"]["ClusterConfiguration"] = buf.getvalue()

    # apply updated kubeadm config map
    buf = io.StringIO()
    yaml.dump(kubeadm_cm, buf)
    filename = uuid.uuid4().hex
    first_control_plane.put(buf, "/tmp/%s.yaml" % filename)
    first_control_plane.sudo("kubectl apply -f /tmp/%s.yaml" % filename)
    first_control_plane.sudo("rm -f /tmp/%s.yaml" % filename)

    return final_feature_list


def finalize_inventory(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    admission_impl = cluster.inventory['rbac']['admission']

    if admission_impl == "psp":
        return finalize_inventory_psp(cluster, inventory_to_finalize)
    elif admission_impl == "pss":
        return finalize_inventory_pss(cluster, inventory_to_finalize)

    return inventory_to_finalize


def finalize_inventory_pss(cluster: KubernetesCluster, inventory_to_finalize: dict) -> dict:
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory_to_finalize
    procedure_config = cluster.procedure_inventory["pss"]

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
    if cluster.context.get('initial_procedure') == 'manage_pss':
        current_config = inventory_to_finalize.setdefault("rbac", {}).setdefault("pss", {})
        current_config["pod-security"] = cluster.procedure_inventory["pss"].get("pod-security", current_config.get("pod-security", "enabled"))
    elif cluster.context.get('initial_procedure') == 'manage_psp':
        current_config = inventory_to_finalize.setdefault("rbac", {}).setdefault("psp", {})
        current_config["pod-security"] = cluster.procedure_inventory["psp"].get("pod-security", current_config.get("pod-security", "enabled"))
    # remove PSP section from cluster_finalyzed.yaml  
    minor_version = int(inventory_to_finalize["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
    if minor_version > 24:
        del inventory_to_finalize["rbac"]["psp"]

    return inventory_to_finalize


def copy_pss(group: NodeGroup) -> Optional[RunnersGroupResult]:
    if group.cluster.inventory['rbac']['admission'] != "pss":
        return None
    if group.cluster.context.get('initial_procedure') == 'manage_pss':
        if not is_security_enabled(group.cluster.inventory) and \
                group.cluster.procedure_inventory["pss"]["pod-security"] != "enabled":
            group.cluster.log.debug("Pod security disabled, skipping pod admission installation...")
            return None
    if group.cluster.context.get('initial_procedure') == 'install':
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


def label_namespace_pss(cluster: KubernetesCluster, manage_type: str) -> None:
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    # set/delete labels on predifined plugins namsespaces
    for ns_name, profile in builtin.get_namespace_to_necessary_pss_profiles(cluster).items():
        target_labels = get_labels_to_ensure_profile(cluster.inventory, profile)
        if manage_type in ["apply", "install"] and target_labels:
            cluster.log.debug(f"Set PSS labels for profile {profile} on namespace {ns_name}")
            command = "kubectl label ns {namespace} {lk}={lv} --overwrite"

        else:  # manage_type == "delete" or default labels are not necessary
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
            if manage_type in ["apply", "install"]:
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
            elif manage_type == "delete":
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
