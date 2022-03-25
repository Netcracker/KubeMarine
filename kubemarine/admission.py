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

import ruamel.yaml
import yaml
from jinja2 import Template

from kubemarine import kubernetes
from kubemarine.core import utils
from kubemarine.core.group import NodeGroup

privileged_policy_filename = "privileged.yaml"
policies_file_path = "./resources/psp/"
tmp_filepath_pattern = "/tmp/%s"

admission_template = "./templates/admission.yaml.j2"
admission_dir = "/etc/kubernetes/pki"
admission_path = "%s/admission.yaml" % admission_dir

psp_list_option = "psp-list"
roles_list_option = "roles-list"
bindings_list_option = "bindings-list"

valid_flags = ["enabled", "disabled"]
provided_oob_policies = ["default", "host-network", "anyuid"]

valid_switches = ["pss", "psp"]
valid_profiles = ["privileged", "baseline", "restricted"]
valid_modes = ['enforce', 'audit', 'warn']
valid_exemptions = ["usernames", "runtimeClasses", "namespaces"]
valid_versions_templ = r"^v1\.\d{1,2}$"

baseline_plugins = {"kubernetes-dashboard": "kubernetes-dashboard"} 
privileged_plugins = {"nginx-ingress-controller": "ingress-nginx", 
                      "local-path-provisioner": "local-path-storage", 
                      "haproxy-ingress-controller": "haproxy-controller"}

loaded_oob_policies = {}

# TODO: When KubeMarine is not support Kubernetes version lower than 1.25, the PSP implementation code should be deleted 

def enrich_inventory_psp(inventory, _):
    global loaded_oob_policies
    loaded_oob_policies = load_oob_policies_files()

    # check flags
    verify_parameter("pod-security", inventory["rbac"]["psp"]["pod-security"], valid_flags)
    for oob_name in provided_oob_policies:
        verify_parameter("oob-policies", inventory["rbac"]["psp"]["oob-policies"][oob_name], valid_flags)

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


def enrich_inventory_pss(inventory, _):
    if not is_security_enabled(inventory):
        return inventory
    # check flags, enforce and logs parameters
    minor_version = int(inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
    if minor_version < 23:
        raise Exception("PSS is not supported properly in Kubernetes version before v1.23")
    verify_parameter("pod-security", inventory["rbac"]["pss"]["pod-security"], valid_flags)
    for item in inventory["rbac"]["pss"]["defaults"]:
        if item.endswith("version"):
            mode = re.split('-',item)[0]
            profile = inventory["rbac"]["pss"]["defaults"][mode]
            verify_version(item, inventory["rbac"]["pss"]["defaults"][item], profile, minor_version)
        else:
            verify_parameter(item, inventory["rbac"]["pss"]["defaults"][item], valid_profiles)
    enabled_admissions = inventory["services"]["kubeadm"]["apiServer"]["extraArgs"].get("feature-gates")
    # add extraArgs to kube-apiserver config
    if enabled_admissions:
        if 'PodSecurity=true' not in enabled_admissions:
                enabled_admissions = "%s,PodSecurity=true" % enabled_admissions
        inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["feature-gates"] = enabled_admissions
        inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
    else:     
        inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["feature-gates"] = "PodSecurity=true"
        inventory["services"]["kubeadm"]["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path

    return inventory


def enrich_inventory(inventory, _):
    verify_parameter("admission", inventory["rbac"]["admission"], valid_switches)
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return enrich_inventory_psp(inventory, _)
    elif admission_impl == "pss":
        return enrich_inventory_pss(inventory, _)


def manage_psp_enrichment(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'manage_psp':
        return inventory
    if "psp" not in cluster.procedure_inventory:
        raise Exception("'manage_psp' config should have 'psp' in its root")

    procedure_config = cluster.procedure_inventory["psp"]
    current_config = cluster.inventory["rbac"]["psp"]

    # check flags
    if "pod-security" in procedure_config:
        verify_parameter("pod-security", procedure_config["pod-security"], valid_flags)
    if "oob-policies" in procedure_config:
        for oob_policy in provided_oob_policies:
            if oob_policy in procedure_config["oob-policies"]:
                verify_parameter("oob-policy", procedure_config["oob-policies"][oob_policy], valid_flags)

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

    # forbid defining 'custom-policies' in procedure inventory
    if "custom-policies" in procedure_config:
        raise Exception("'manage_psp' procedure should not be configured using 'custom-policies', "
                        "use 'add-policies' or 'delete-policies' instead")

    return inventory


def verify_parameter(owner, value, parameters):
    if value not in parameters:
        raise Exception("incorrect value for %s, valid values: %s" % (owner, parameters))


def verify_custom(custom_scope):
    psp_list = custom_scope.get(psp_list_option, None)
    if psp_list:
        verify_custom_list(psp_list, "PSP", ["PodSecurityPolicy"])

    roles_list = custom_scope.get(roles_list_option, None)
    if roles_list:
        verify_custom_list(roles_list, "role", ["Role", "ClusterRole"])

    bindings_list = custom_scope.get(bindings_list_option, None)
    if bindings_list:
        verify_custom_list(bindings_list, "binding", ["RoleBinding", "ClusterRoleBinding"])


def verify_custom_list(custom_list, type, supported_kinds):
    for item in custom_list:
        if item["kind"] not in supported_kinds:
            raise Exception("Type %s should have %s kind" % (type, supported_kinds))
        # forbid using 'oob-' prefix in order to avoid conflicts of our policies and users policies
        if item["metadata"]["name"].startswith("oob-"):
            raise Exception("Name %s is not allowed for custom %s" % (item["metadata"]["name"], type))


def verify_version(owner, version, profile, minor_version_cfg):
    # check Kubernetes version and admission config matching
    if profile == "restricted" and version != "latest":
        result = re.match(valid_versions_templ, version)
        if result is None:
            raise Exception("incorrect Kubernetes version %s, valid version(for example): v1.23" % owner)
        minor_version = int(version.split('.')[1])
        if minor_version > minor_version_cfg:
            raise Exception("%s version must not be higher than Kubernetes version" % owner)
    elif profile != "restricted" and version != "latest":
        raise Exception("incorrect value for %s, valid value is 'latest'" % owner)


def finalize_inventory_psp(cluster, inventory_to_finalize):
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


def merge_custom_policies(old_policies, added_policies, deleted_policies):
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


def merge_policy_lists(old_list, added_list, deleted_list):
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


def install_psp_task(cluster):
    if not is_security_enabled(cluster.inventory):
        cluster.log.debug("Pod security disabled, skipping policies installation...")
        return

    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Installing OOB policies...")
    first_master.call(manage_policies,
                      manage_type="apply",
                      manage_scope=resolve_oob_scope(cluster.inventory["rbac"]["psp"]["oob-policies"], "enabled"))

    cluster.log.debug("Installing custom policies...")
    first_master.call(manage_policies,
                      manage_type="apply",
                      manage_scope=cluster.inventory["rbac"]["psp"]["custom-policies"])


def delete_custom_task(cluster):
    if "delete-policies" not in cluster.procedure_inventory["psp"]:
        cluster.log.debug("No 'delete-policies' specified, skipping...")
        return

    cluster.log.debug("Deleting custom 'delete-policies'")
    first_master = cluster.nodes["master"].get_first_member()
    first_master.call(manage_policies,
                      manage_type="delete",
                      manage_scope=cluster.procedure_inventory["psp"]["delete-policies"])


def add_custom_task(cluster):
    if "add-policies" not in cluster.procedure_inventory["psp"]:
        cluster.log.debug("No 'add-policies' specified, skipping...")
        return

    cluster.log.debug("Applying custom 'add-policies'")
    first_master = cluster.nodes["master"].get_first_member()
    first_master.call(manage_policies,
                      manage_type="apply",
                      manage_scope=cluster.procedure_inventory["psp"]["add-policies"])


def reconfigure_oob_task(cluster):
    target_security_state = cluster.procedure_inventory["psp"].get("pod-security")
    oob_policies = cluster.procedure_inventory["psp"].get("oob-policies")

    # reconfigure OOB only if state will be changed, or OOB configuration was changed
    if not target_security_state and not oob_policies:
        cluster.log.debug("No need to reconfigure OOB policies, skipping...")
        return

    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Deleting all OOB policies...")
    first_master.call(delete_privileged_policy)
    first_master.call(manage_policies, manage_type="delete", manage_scope=resolve_oob_scope(loaded_oob_policies, "all"))

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
    first_master.call(apply_privileged_policy)
    first_master.call(manage_policies, manage_type="apply", manage_scope=resolve_oob_scope(policies_to_recreate, "all"))


def reconfigure_plugin_task(cluster):
    target_state = cluster.procedure_inventory["psp"].get("pod-security")

    if not target_state:
        cluster.log.debug("Security plugin will not be reconfigured")
        return

    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Updating kubeadm config map")
    result = first_master.call(update_kubeadm_configmap, target_state=target_state)
    final_admission_plugins_list = list(result.values())[0]

    # update api-server config on all masters
    cluster.log.debug("Updating kube-apiserver configs on masters")
    cluster.nodes["master"].call(update_kubeapi_config, options_list=final_admission_plugins_list)


def restart_pods_task(cluster, disable_eviction=False):
    if cluster.context.get('initial_procedure') == 'manage_pss':
        is_restart = cluster.procedure_inventory["pss"].get("restart-pods", False)
        if not is_restart and cluster.procedure_inventory["pss"]["pod-security"] == "disabled":
            return

    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Drain-Uncordon all nodes to restart pods")
    kube_nodes = cluster.nodes["master"].include_group(cluster.nodes["worker"])
    for node in kube_nodes.get_ordered_members_list(provide_node_configs=True):
        first_master.sudo(
            kubernetes.prepare_drain_command(node, cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                             cluster.globals, disable_eviction, cluster.nodes), hide=False)
        first_master.sudo("kubectl uncordon %s" % node["name"], hide=False)

    cluster.log.debug("Restarting daemon-sets...")
    daemon_sets = yaml.load(list(first_master.sudo("kubectl get ds -A -o yaml").values())[0].stdout)
    for ds in daemon_sets["items"]:
        first_master.sudo("kubectl rollout restart ds %s -n %s" % (ds["metadata"]["name"], ds["metadata"]["namespace"]))

    # we do not know to wait for, only for system pods maybe
    cluster.log.debug("Waiting for system pods...")
    first_master.call(kubernetes.wait_for_any_pods, connection=None)


def update_kubeadm_configmap_psp(first_master, target_state):
    yaml = ruamel.yaml.YAML()

    # load kubeadm config map and retrieve cluster config
    result = first_master.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
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
    first_master.put(buf, "/tmp/%s.yaml" % filename)
    first_master.sudo("kubectl apply -f /tmp/%s.yaml" % filename)
    first_master.sudo("rm -f /tmp/%s.yaml" % filename)

    return final_plugins_string


def update_kubeadm_configmap(first_master, target_state):
    admission_impl = first_master.cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        return update_kubeadm_configmap_psp(first_master, target_state)
    elif admission_impl == "pss":
        return update_kubeadm_configmap_pss(first_master, target_state)


def update_kubeapi_config_psp(masters, plugins_list):
    yaml = ruamel.yaml.YAML()

    for master in masters.get_ordered_members_list():
        result = master.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")

        # update kube-apiserver config with updated plugins list
        conf = yaml.load(list(result.values())[0].stdout)
        new_command = [cmd for cmd in conf["spec"]["containers"][0]["command"] if "enable-admission-plugins" not in cmd]
        new_command.append("--enable-admission-plugins=%s" % plugins_list)
        conf["spec"]["containers"][0]["command"] = new_command

        # place updated config on master
        buf = io.StringIO()
        yaml.dump(conf, buf)
        master.put(buf, "/etc/kubernetes/manifests/kube-apiserver.yaml", sudo=True)

    # force kube-apiserver pod restart, then wait for api to become available
    masters.get_first_member().call(utils.wait_command_successful,
                                    command="kubectl delete pod -n kube-system "
                                            "$(sudo kubectl get pod -n kube-system "
                                            "| grep 'kube-apiserver' | awk '{ print $1 }')")
    masters.get_first_member().call(utils.wait_command_successful, command="kubectl get pod -A")


def update_kubeapi_config(masters, options_list):
    admission_impl = masters.cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        return update_kubeapi_config_psp(masters, options_list)
    elif admission_impl == "pss":
        return update_kubeapi_config_pss(masters, options_list)

def is_security_enabled(inventory):
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return inventory["rbac"]["psp"]["pod-security"] == "enabled"
    elif admission_impl == "pss":
        return inventory["rbac"]["pss"]["pod-security"] == "enabled"


def apply_privileged_policy(group):
    return manage_privileged_from_file(group, privileged_policy_filename, "apply")


def delete_privileged_policy(group):
    return manage_privileged_from_file(group, privileged_policy_filename, "delete")


def apply_admission(group):
    admission_impl = group.cluster.inventory['rbac']['admission']
    if is_security_enabled(group.cluster.inventory):
        if admission_impl == "psp":
            group.cluster.log.debug("Setting up privileged psp...")
            apply_privileged_policy(group)
        elif admission_impl == "pss":
            group.cluster.log.debug("Setting up default pss...")
            apply_default_pss(group.cluster)


def apply_default_pss(cluster):
    procedure_config = cluster.procedure_inventory["pss"]
    current_config = cluster.inventory["rbac"]["pss"]
    if (procedure_config["pod-security"] == "enabled" and current_config["pod-security"] == "enabled") or \
            (procedure_config["pod-security"] == "enabled" and current_config["pod-security"] == "disabled"):    
        return manage_pss(cluster, "apply")


def delete_default_pss(cluster):
    procedure_config = cluster.procedure_inventory["pss"]
    current_config = cluster.inventory["rbac"]["pss"]
    if procedure_config["pod-security"] == "disabled" and current_config["pod-security"] == "enabled":
        return manage_pss(cluster, "delete")


def manage_privileged_from_file(group: NodeGroup, filename, manage_type):
    if manage_type not in ["apply", "delete"]:
        raise Exception("unexpected manage type for privileged policy")
    local_path = utils.get_resource_absolute_path(os.path.join(policies_file_path, filename), script_relative=True)
    remote_path = tmp_filepath_pattern % filename
    group.put(local_path, remote_path, backup=True, sudo=True, binary=False)

    return group.sudo("kubectl %s -f %s" % (manage_type, remote_path), warn=True)


def resolve_oob_scope(oob_policies_conf, selector):
    result = {
        psp_list_option: [],
        roles_list_option: [],
        bindings_list_option: []
    }

    for key, value in oob_policies_conf.items():
        if key not in provided_oob_policies:
            raise Exception("Unknown oob policy configured")
        if value == selector or selector == "all":
            policy = loaded_oob_policies[key]
            if "psp" in policy:
                result[psp_list_option].append(policy["psp"])
            if "role" in policy:
                result[roles_list_option].append(policy["role"])
            if "binding" in policy:
                result[bindings_list_option].append(policy["binding"])

    return result


def load_oob_policies_files():
    oob_policies = {}
    for oob_name in provided_oob_policies:
        local_path = utils.get_resource_absolute_path(os.path.join(policies_file_path, "%s.yaml" % oob_name),
                                                      script_relative=True)
        with open(local_path) as stream:
            oob_policies[oob_name] = yaml.safe_load(stream)

    return oob_policies


def manage_policies(group, manage_type, manage_scope):
    psp_to_manage = manage_scope.get(psp_list_option, None)
    roles_to_manage = manage_scope.get(roles_list_option, None)
    bindings_to_manage = manage_scope.get(bindings_list_option, None)

    if not psp_to_manage and not roles_to_manage and not bindings_to_manage:
        group.cluster.log.verbose("No policies to %s" % manage_type)
        return

    template = collect_policies_template(psp_to_manage, roles_to_manage, bindings_to_manage)
    filename = uuid.uuid4().hex
    remote_path = tmp_filepath_pattern % filename
    group.put(io.StringIO(template), remote_path, backup=True, sudo=True)
    result = group.sudo("kubectl %s -f %s" % (manage_type, remote_path), warn=True)
    group.sudo("rm -f %s" % remote_path)
    return result


def collect_policies_template(psp_list, roles_list, bindings_list):
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


def resolve_final_plugins_list(cluster_config, target_state):
    if "enable-admission-plugins" not in cluster_config["apiServer"]["extraArgs"]:
        if target_state == "enabled":
            return "PodSecurityPolicy"
        else:
            return None
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


def install(cluster):
    admission_impl = cluster.inventory['rbac']['admission']
    if admission_impl == "psp":
        return install_psp_task(cluster)
    elif admission_impl == "pss":
        return install_pss_task(cluster)


def install_pss_task(cluster):
    if not is_security_enabled(cluster.inventory):
        cluster.log.debug("Pod security disabled, skipping pod admission installation...")
        return

    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Installing default configuration...")
    first_master.call(manage_pss, manage_type="apply")


def manage_pss_enrichment(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory
    if "pss" not in cluster.procedure_inventory:
        raise Exception("'manage_pss' config should have 'pss' in its root")
    if "pod-security" not in cluster.procedure_inventory["pss"]:
        raise Exception("Procedure config should include 'pod-security'")

    procedure_config = cluster.procedure_inventory["pss"]
    current_config = cluster.inventory["rbac"]["pss"]
    minor_version = int(cluster.inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])

    if is_security_enabled(inventory) and procedure_config["pod-security"] == "enabled": 
        # check the difference between current and procedure config
        diff = 0
        if "defaults" in procedure_config:
            for mode in procedure_config["defaults"]:
                if procedure_config["defaults"][mode] != current_config["defaults"][mode]:
                    diff += 1
        if "exemptions" in procedure_config:
            for mode in procedure_config["exemptions"]:
                if procedure_config["exemptions"][mode] != current_config["exemptions"][mode]:
                    diff += 1
        if diff == 0:
            raise Exception("'defaults' and 'exemtions' sections in procedure config and current config are equal. There is nothing to change")

    if not is_security_enabled(inventory) and procedure_config["pod-security"] == "disabled":
        raise Exception("both 'pod-security' in procedure config and current config are 'disabled'. There is nothing to change")

    # check flags, profiles; enrich inventory
    verify_parameter("pod-security", procedure_config["pod-security"], valid_flags)
    if "defaults" in procedure_config:
        for item in procedure_config["defaults"]:
            if item.endswith("version"):
                mode = re.split('-',item)[0]
                if mode in procedure_config["defaults"]:
                    profile = procedure_config["defaults"][mode]
                else:
                    profile = current_config["defaults"][mode]
                verify_version(item, procedure_config["defaults"][item], profile, minor_version)
            else:
                verify_parameter(item, procedure_config["defaults"][item], valid_profiles)
            inventory["rbac"]["pss"]["defaults"][item] = procedure_config["defaults"][item]
    if "exemptions" in procedure_config:
        for item in procedure_config["exemtions"]:
            if type(item) is list:
                inventory["rbac"]["pss"]["exemtions"][item] = procedure_config["exemtions"][item]
    if "namespaces" in procedure_config:
        for namespace in procedure_config["namespaces"]:
            if item.endswith("version"):
                mode = re.split('-',item)[0]
                if mode in procedure_config["defaults"]:
                    profile = procedure_config["defaults"][mode]
                else:
                    profile = current_config["defaults"][mode]
                verify_version(item, procedure_config["defaults"][item], profile, minor_version)
            else:
                verify_parameter(item, procedure_config["defaults"][item], valid_profiles)

    return inventory


def manage_enrichment(inventory, cluster):
    admission_impl = inventory['rbac']['admission']
    if admission_impl == "psp":
        return manage_psp_enrichment(inventory, cluster)
    elif admission_impl == "pss":
        return manage_pss_enrichment(inventory, cluster)


def manage_pss(cluster, manage_type):
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return

    first_master = cluster.nodes["master"].get_first_member()
    if manage_type == "apply":
        # set labels for predifined plugins namespaces and namespaces defined in procedure config
        label_namespace_pss(cluster, manage_type)
        # copy admission config on masters
        copy_pss(cluster.nodes["master"])
    
        cluster.log.debug("Updating kubeadm config map")
        result = first_master.call(update_kubeadm_configmap, target_state="enabled")
        final_features_list = list(result.values())[0]
    
        # update api-server config on all masters
        cluster.log.debug("Updating kube-apiserver configs on masters")
        cluster.nodes["master"].call(update_kubeapi_config_pss, features_list=final_features_list)
    elif manage_type == "delete":
        # set labels for predifined plugins namespaces and namespaces defined in procedure config
        label_namespace_pss(cluster, manage_type)

        result = first_master.call(update_kubeadm_configmap, target_state="disabled")
        final_features_list = list(result.values())[0]

        # update api-server config on all masters
        cluster.log.debug("Updating kube-apiserver configs on masters")
        cluster.nodes["master"].call(update_kubeapi_config_pss, features_list=final_features_list)

        # erase PSS admission config 
        cluster.log.debug("Erase admission configuration... %s" % admission_path)
        group = cluster.nodes["master"]
        group.sudo("rm -f %s" % admission_path, warn=True)


def update_kubeapi_config_pss(masters, features_list):
    yaml = ruamel.yaml.YAML()

    for master in masters.get_ordered_members_list():
        result = master.sudo("cat /etc/kubernetes/manifests/kube-apiserver.yaml")

        # update kube-apiserver config with updated features list
        conf = yaml.load(list(result.values())[0].stdout)
        new_command = [cmd for cmd in conf["spec"]["containers"][0]["command"]]
        if len(features_list) != 0:
            if 'PodSecurity=true' in features_list:
                new_command.append("--admission-control-config-file=%s" % admission_path)
            else:
                new_command.append("--admission-control-config-file=''")
            new_command.append("--feature-gates=%s" % features_list)
        else:
            for item in conf["spec"]["containers"][0]["command"]:
                if item.startswith("--"):
                    key = re.split('=',item)[0]
                    value = re.search('=(.*)$', item).group(1)
                    if key in ["--feature-gates", "--admission-control-config-file"]:
                        del_option = "%s=%s" % (key, value)
                        new_command.remove(del_option)

        conf["spec"]["containers"][0]["command"] = new_command

        # place updated config on master
        buf = io.StringIO()
        yaml.dump(conf, buf)
        master.put(buf, "/etc/kubernetes/manifests/kube-apiserver.yaml", sudo=True)

        # force kube-apiserver pod restart, then wait for api to become available
        if master.cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
            master.call(utils.wait_command_successful, command="crictl rm -f "
                                                       "$(sudo crictl ps --name kube-apiserver -q)")
        else:
            master.call(utils.wait_command_successful, command="docker stop "
                                                       "$(sudo docker ps -f 'name=k8s_kube-apiserver'"
                                                       " | awk '{print $1}')")
        masters.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")


def update_kubeadm_configmap_pss(first_master, target_state):
    yaml = ruamel.yaml.YAML()

    final_feature_list = ""

    # load kubeadm config map and retrieve cluster config
    result = first_master.sudo("kubectl get cm kubeadm-config -n kube-system -o yaml")
    kubeadm_cm = yaml.load(list(result.values())[0].stdout)
    cluster_config = yaml.load(kubeadm_cm["data"]["ClusterConfiguration"])
    
    # update kubeadm config map with feature list
    if target_state == "enabled":
        if "feature-gates" in cluster_config["apiServer"]["extraArgs"]:
            enabled_admissions = cluster_config["apiServer"]["extraArgs"]["feature-gates"]
            if 'PodSecurity=true' not in enabled_admissions:
                enabled_admissions = "%s,PodSecurity=true" % enabled_admissions
                cluster_config["apiServer"]["extraArgs"]["feature-gates"] = enabled_admissions
                cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
                final_feature_list = enabled_admissions
        else:
            cluster_config["apiServer"]["extraArgs"]["feature-gates"] = "PodSecurity=true"
            cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"] = admission_path
            final_feature_list = "PodSecurity=true"
    elif target_state == "disabled":
        feature_list = cluster_config["apiServer"]["extraArgs"]["feature-gates"].replace("PodSecurity=true", "")
        final_feature_list = feature_list.replace(",,", ",")
        if len(final_feature_list) == 0:
            del cluster_config["apiServer"]["extraArgs"]["feature-gates"]
            del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]
        else:
            cluster_config["apiServer"]["extraArgs"]["feature-gates"] = final_feature_list
            del cluster_config["apiServer"]["extraArgs"]["admission-control-config-file"]

    buf = io.StringIO()
    yaml.dump(cluster_config, buf)
    kubeadm_cm["data"]["ClusterConfiguration"] = buf.getvalue()

    # apply updated kubeadm config map
    buf = io.StringIO()
    yaml.dump(kubeadm_cm, buf)
    filename = uuid.uuid4().hex
    first_master.put(buf, "/tmp/%s.yaml" % filename)
    first_master.sudo("kubectl apply -f /tmp/%s.yaml" % filename)
    first_master.sudo("rm -f /tmp/%s.yaml" % filename)
    
    return final_feature_list


def finalize_inventory(cluster, inventory_to_finalize):
    admission_impl = cluster.inventory['rbac']['admission']

    if admission_impl == "psp":
        return finalize_inventory_psp(cluster, inventory_to_finalize)
    elif admission_impl == "pss":
        return finalize_inventory_pss(cluster, inventory_to_finalize)


def finalize_inventory_pss(cluster, inventory_to_finalize):
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return inventory_to_finalize
    procedure_config = cluster.procedure_inventory["pss"]

    if "rbac" not in inventory_to_finalize:
        inventory_to_finalize["rbac"] = {}
    if "pss" not in inventory_to_finalize["rbac"]:
        inventory_to_finalize["rbac"]["pss"] = {}
    current_config = inventory_to_finalize["rbac"]["pss"]

    # merge flags from procedure config and cluster config
    current_config["pod-security"] = procedure_config.get("pod-security", current_config.get("pod-security", "enabled"))
    if "defaults" in procedure_config:
        if "defaults" not in current_config:
            current_config["defaults"] = procedure_config["defaults"]
        else:
            for default_option in procedure_config["defaults"]:
                current_config["defaults"][default_option] = procedure_config["defaults"][default_option]
    if "exemptions" in procedure_config:
        if "exemptions" not in current_config:
            current_config["exemptions"] = procedure_config["exemptions"]
        else:
            for exemption in procedure_config["exemptions"]:
                current_config["exemptions"][exemption] = procedure_config["exemptions"][exemption]

    return inventory_to_finalize


def copy_pss(group):
    if  group.cluster.inventory['rbac']['admission'] !=  "pss":
        return
    if not is_security_enabled(group.cluster.inventory) and group.cluster.procedure_inventory["pss"]["pod-security"] != "enabled":
        group.cluster.log.debug("Pod security disabled, skipping pod admission installation...")
        return

    defaults = group.cluster.inventory["rbac"]["pss"]["defaults"]
    exemptions = group.cluster.inventory["rbac"]["pss"]["exemptions"]
    # create admission config from template and cluster.yaml
    admission_config = Template(open(utils.get_resource_absolute_path(admission_template, script_relative=True)).read())\
                       .render(defaults=defaults,exemptions=exemptions)

    # put admission config on every masters
    filename = uuid.uuid4().hex
    remote_path = tmp_filepath_pattern % filename
    group.cluster.log.debug("Copy admission config: %s, %s" % (remote_path, admission_path))
    group.put(io.StringIO(admission_config), remote_path, backup=True, sudo=True)
    group.sudo("mkdir -p %s" % admission_dir, warn=True)
    result = group.sudo("cp %s %s" % (remote_path, admission_path), warn=True)
    group.sudo("rm -f %s" % remote_path)

    return result


def label_namespace_pss(cluster, manage_type):
    if cluster.context.get('initial_procedure') != 'manage_pss':
        return
    first_master = cluster.nodes["master"].get_first_member()
    # get default PSS profile
    profile = cluster.inventory["rbac"]["pss"]["defaults"]["enforce"]
    for plugin in cluster.inventory["plugins"]:
        is_install = cluster.inventory["plugins"][plugin].get("install")
        # set/delete label 'pod-security.kubernetes.io/enforce: privileged' for local provisioner and ingress namespaces
        if is_install == True and plugin in privileged_plugins.keys() and profile != "privileged":
            if manage_type == "apply":
                cluster.log.debug("Set PSS labels on namespace %s" % privileged_plugins[plugin])
                for mode in valid_modes:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s=%s --overwrite" 
                                      % (privileged_plugins[plugin], mode, "privileged"))
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-version=%s --overwrite" 
                                      % (privileged_plugins[plugin], mode, "latest"))
            elif manage_type == "delete":
                cluster.log.debug("Delete PSS labels from namespace %s" % privileged_plugins[plugin])
                for mode in valid_modes:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-" 
                                       % (privileged_plugins[plugin], mode))
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-version-" 
                                       % (privileged_plugins[plugin], mode))
        # set/delete label 'pod-security.kubernetes.io/enforce: baseline' for kubernetes dashboard
        elif is_install == True and plugin in baseline_plugins.keys() and profile == "restricted":
            if manage_type == "apply":
                cluster.log.debug("Set PSS labels on namespace %s" % baseline_plugins[plugin])
                for mode in valid_modes:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s=%s --overwrite" 
                                      % (baseline_plugins[plugin], mode, "baseline"))
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-version=%s --overwrite" 
                                      % (baseline_plugins[plugin], mode, "latest"))
            elif manage_type == "delete":
                cluster.log.debug("Delete PSS labels from namespace %s" % baseline_plugins[plugin])
                for mode in valid_modes:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-" 
                                       % (baseline_plugins[plugin], mode))
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-version-" 
                                       % (baseline_plugins[plugin], mode))

    procedure_config = cluster.procedure_inventory["pss"]
    namespaces = procedure_config.get("namespaces")
    # get the list of namespaces that should be labeled then set/delete labels
    if namespaces:
        for namespace in namespaces:
            if manage_type == "apply":
                cluster.log.debug("Set PSS labels on namespace %s" % namespace)
                for mode in namespaces[namespace]:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s=%s --overwrite" 
                                      % (namespace, mode, namespaces[namespace][mode]))
            elif manage_type == "delete":
                cluster.log.debug("Delete PSS labels on namespace %s" % namespace)
                for mode in namespaces[namespace]:
                    first_master.sudo("kubectl label ns %s pod-security.kubernetes.io/%s-" % (namespace, mode))

