import io
import os
import uuid

import ruamel.yaml
import yaml

from kubetool import kubernetes
from kubetool.core import utils
from kubetool.core.group import NodeGroup

privileged_policy_filename = "privileged.yaml"
policies_file_path = "./resources/psp/"
tmp_filepath_pattern = "/tmp/%s"

psp_list_option = "psp-list"
roles_list_option = "roles-list"
bindings_list_option = "bindings-list"

valid_flags = ["enabled", "disabled"]
provided_oob_policies = ["default", "host-network", "anyuid"]

loaded_oob_policies = {}


def enrich_inventory(inventory, _):
    global loaded_oob_policies
    loaded_oob_policies = load_oob_policies_files()

    # check flags
    verify_flag("pod-security", inventory["rbac"]["psp"]["pod-security"])
    for oob_name in provided_oob_policies:
        verify_flag("oob-policies", inventory["rbac"]["psp"]["oob-policies"][oob_name])

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


def manage_psp_enrichment(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'manage_psp':
        return inventory
    if "psp" not in cluster.procedure_inventory:
        raise Exception("'manage_psp' config should have 'psp' in its root")

    procedure_config = cluster.procedure_inventory["psp"]
    current_config = cluster.inventory["rbac"]["psp"]

    # check flags
    if "pod-security" in procedure_config:
        verify_flag("pod-security", procedure_config["pod-security"])
    if "oob-policies" in procedure_config:
        for oob_policy in provided_oob_policies:
            if oob_policy in procedure_config["oob-policies"]:
                verify_flag("oob-policy", procedure_config["oob-policies"][oob_policy])

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


def verify_flag(owner, value):
    if value not in valid_flags:
        raise Exception("incorrect value for %s, valid values: %s" % (owner, valid_flags))


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


def finalize_inventory(cluster, inventory_to_finalize):
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
    cluster.nodes["master"].call(update_kubeapi_config, plugins_list=final_admission_plugins_list)


def restart_pods_task(cluster, disable_eviction=False):
    first_master = cluster.nodes["master"].get_first_member()

    cluster.log.debug("Drain-Uncordon all nodes to restart pods")
    kube_nodes = cluster.nodes["master"].include_group(cluster.nodes["worker"])
    for node in kube_nodes.get_ordered_members_list(provide_node_configs=True):
        first_master.sudo(
            kubernetes.prepare_drain_command(node, cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                             cluster.globals, disable_eviction, cluster.nodes), hide=False)
        first_master.sudo("kubectl uncordon %s" % node["name"], hide=False)

    cluster.log.debug("Restarting daemon-sets...")
    daemon_sets = yaml.safe_load(list(first_master.sudo("kubectl get ds -A -o yaml").values())[0].stdout)
    for ds in daemon_sets["items"]:
        first_master.sudo("kubectl rollout restart ds %s -n %s" % (ds["metadata"]["name"], ds["metadata"]["namespace"]))

    # we do not know to wait for, only for system pods maybe
    cluster.log.debug("Waiting for system pods...")
    first_master.call(kubernetes.wait_for_any_pods, connection=None)


def update_kubeadm_configmap(first_master, target_state):
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


def update_kubeapi_config(masters, plugins_list):
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


def is_security_enabled(inventory):
    return inventory["rbac"]["psp"]["pod-security"] == "enabled"


def apply_privileged_policy(group):
    return manage_privileged_from_file(group, privileged_policy_filename, "apply")


def delete_privileged_policy(group):
    return manage_privileged_from_file(group, privileged_policy_filename, "delete")


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
