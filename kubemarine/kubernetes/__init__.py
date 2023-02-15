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
import math
import os
import time
from copy import deepcopy
from typing import List, Dict, Union

import ruamel.yaml
import yaml
from jinja2 import Template

from kubemarine import system, plugins, admission, etcd, packages
from kubemarine.core import utils, static, summary
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup
from kubemarine.core.errors import KME

version_coredns_path_breakage = "v1.21.2"

ERROR_DOWNGRADE='Kubernetes old version \"%s\" is greater than new one \"%s\"'
ERROR_SAME='Kubernetes old version \"%s\" is the same as new one \"%s\"'
ERROR_MAJOR_RANGE_EXCEEDED='Major version \"%s\" rises to new \"%s\" more than one'
ERROR_MINOR_RANGE_EXCEEDED='Minor version \"%s\" rises to new \"%s\" more than one'


def add_node_enrichment(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'add_node':
        return inventory

    # adding role "new_node" for all specified new nodes and putting these nodes to all "nodes" list
    for new_node in cluster.procedure_inventory.get("nodes", []):
        # deepcopy is necessary, otherwise role append will happen in procedure_inventory too
        node = deepcopy(new_node)
        node["roles"].append("add_node")
        inventory["nodes"].append(node)

    if "vrrp_ips" in cluster.procedure_inventory:
        utils.merge_vrrp_ips(cluster.procedure_inventory, inventory)

    return inventory


def remove_node_enrichment(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'remove_node':
        return inventory

    # adding role "remove_node" for all specified nodes
    node_names_to_remove = [node['name'] for node in cluster.procedure_inventory.get("nodes", [])]
    for i, node in enumerate(inventory['nodes']):
        if node['name'] in node_names_to_remove:
            inventory['nodes'][i]['roles'].append('remove_node')

    return inventory


def enrich_upgrade_inventory(inventory, cluster):
    if cluster.context.get('initial_procedure') == 'upgrade':
        if not inventory.get('services'):
            inventory['services'] = {}
        if not inventory['services'].get('kubeadm'):
            inventory['services']['kubeadm'] = {}
        cluster.context['initial_kubernetes_version'] = inventory['services']['kubeadm']['kubernetesVersion']
        inventory['services']['kubeadm']['kubernetesVersion'] = cluster.context['upgrade_version']

        test_version_upgrade_possible(cluster.context['initial_kubernetes_version'], cluster.context['upgrade_version'])
        cluster.log.info(
            '------------------------------------------\nUPGRADING KUBERNETES %s ⭢ %s\n------------------------------------------' % (
            cluster.context['initial_kubernetes_version'], cluster.context['upgrade_version']))
    return inventory


def version_higher_or_equal(version, compared_version):
    '''
    The method checks target Kubernetes version, is it more/equal than compared_version.
    '''
    compared_version_list = compared_version.replace('v', '').split('.')
    version_list = version.replace('v', '').split('.')
    if int(version_list[0]) > int(compared_version_list[0]):
        return True
    if int(version_list[0]) == int(compared_version_list[0]):
        if int(version_list[1]) > int(compared_version_list[1]):
            return True
        if int(version_list[1]) == int(compared_version_list[1]):
            if int(version_list[2]) >= int(compared_version_list[2]):
                return True
    return False


def enrich_inventory(inventory, cluster):
    if version_higher_or_equal(inventory['services']['kubeadm']['kubernetesVersion'], version_coredns_path_breakage):
        repository = inventory['services']['kubeadm'].get('imageRepository', "")
        if repository:
            inventory['services']['kubeadm']['dns'] = {}
            inventory['services']['kubeadm']['dns']['imageRepository'] = ("%s/coredns" % repository)
    # if user redefined apiServer as, string, for example?
    if not isinstance(inventory["services"]["kubeadm"].get('apiServer'), dict):
        inventory["services"]["kubeadm"]['apiServer'] = {}

    # if user redefined apiServer.certSANs as, string, or removed it, for example?
    if not isinstance(inventory["services"]["kubeadm"]['apiServer'].get('certSANs'), list):
        inventory["services"]["kubeadm"]['apiServer']['certSANs'] = []

    certsans = inventory["services"]["kubeadm"]['apiServer']['certSANs']

    # do not overwrite apiServer.certSANs, but append - may be user specified something already there?
    for node in inventory["nodes"]:
        if 'balancer' in node['roles'] or 'control-plane' in node['roles']:
            inventory["services"]["kubeadm"]['apiServer']['certSANs'].append(node['internal_address'])
            inventory["services"]["kubeadm"]['apiServer']['certSANs'].append(node['name'])
            if node.get('address') is not None and node['address'] not in certsans:
                inventory["services"]["kubeadm"]['apiServer']['certSANs'].append(node['address'])

    if inventory["vrrp_ips"] is not None:
        for item in inventory["vrrp_ips"]:
            inventory["services"]["kubeadm"]['apiServer']['certSANs'].append(item['ip'])
            if item.get("floating_ip"):
                inventory["services"]["kubeadm"]["apiServer"]["certSANs"].append(item["floating_ip"])

    if inventory.get("public_cluster_ip"):
        if inventory["public_cluster_ip"] not in inventory["services"]["kubeadm"]["apiServer"]["certSANs"]:
            inventory["services"]["kubeadm"]["apiServer"]["certSANs"].append(inventory["public_cluster_ip"])

    any_worker_found = False

    # validating node labels and configuring additional labels
    for node in inventory["nodes"]:
        if "control-plane" not in node["roles"] and "worker" not in node["roles"]:
            if "labels" in node:
                raise Exception("Only 'worker' or 'control-plane' nodes can have labels, "
                                "but found label on %s, roles: %s" % (node["name"], node["roles"]))
            if "taints" in node:
                raise Exception("Only 'worker' or 'control-plane' nodes can have taints, "
                                "but found taints on %s, roles: %s" % (node["name"], node["roles"]))
            continue

        if "worker" in node["roles"]:
            any_worker_found = True

            if "labels" not in node:
                node["labels"] = {}
            node["labels"]["node-role.kubernetes.io/worker"] = "worker"

    # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
    if "v1.21" in inventory["services"]["kubeadm"]["kubernetesVersion"]:
        # use first control plane internal address as a default bind-address
        # for other control-planes we override it during initialization
        # todo: use patches approach for node-specific options
        for node in inventory["nodes"]:
            if "control-plane" in node["roles"] and "remove_node" not in node["roles"]:
                inventory["services"]["kubeadm"]['apiServer']['extraArgs']['bind-address'] = node['internal_address']
                break

    # validate nodes in kubeadm_patches (groups are validated with JSON schema)
    for node in inventory["nodes"]:
        for control_plane_item in inventory["services"]["kubeadm_patches"]:
            for i in inventory["services"]["kubeadm_patches"][control_plane_item]:
                if i.get('nodes') is not None:
                    for n in i['nodes']:
                        if node['name'] == n:
                            if control_plane_item == 'kubelet' and 'control-plane' not in node['roles'] and 'worker' not in node['roles']:
                                raise Exception("%s patch can be uploaded only to control-plane or worker nodes" % control_plane_item)
                            if control_plane_item != 'kubelet' and ('control-plane' not in node['roles']):
                                raise Exception("%s patch can be uploaded only to control-plane nodes" % control_plane_item)

    if not any_worker_found:
        raise KME("KME0004")

    # check ignorePreflightErrors value and add mandatory errors from defaults.yaml if they're absent
    default_preflight_errors = static.DEFAULTS["services"]["kubeadm_flags"]["ignorePreflightErrors"].split(",")
    preflight_errors = inventory["services"]["kubeadm_flags"]["ignorePreflightErrors"].split(",")

    preflight_errors.extend(default_preflight_errors)
    inventory["services"]["kubeadm_flags"]["ignorePreflightErrors"] = ",".join(set(preflight_errors))

    return inventory


def reset_installation_env(group: NodeGroup):
    log = group.cluster.log

    log.debug("Cleaning up previous installation...")

    cluster = group.cluster

    drain_timeout = cluster.procedure_inventory.get('drain_timeout')
    grace_period = cluster.procedure_inventory.get('grace_period')

    # if we perform "add" or "remove" node procedure
    # then we need to additionally perform "drain" and "delete" during reset
    nodes_for_draining = cluster.make_group([])

    # perform FULL reset only for "add" or "remove" procedures
    # do not perform full reset on cluster (re)installation, it could hang on last etcd member
    # nodes should be deleted only during "add" or "remove" procedures
    is_add_or_remove_procedure = True

    nodes_for_manual_etcd_remove = cluster.make_group([])

    if not group.get_nodes_for_removal().is_empty():
        # this is remove_node procedure
        active_nodes = group.get_online_nodes(True)

        # We need to manually remove members from etcd for "remove" procedure,
        # only if corresponding nodes are not active.
        # Otherwise, they will be removed by "kubeadm reset" command.
        nodes_for_manual_etcd_remove = group.exclude_group(active_nodes)

        # kubectl drain command hands on till timeout is exceeded for nodes which are off
        # so we should drain only active nodes
        nodes_for_draining = active_nodes
    else:
        # in other case we consider all nodes are active
        active_nodes = group

        if not group.get_new_nodes().is_empty():
            # this is add_node procedure
            nodes_for_draining = group
        else:
            # this is install procedure
            is_add_or_remove_procedure = False

    if not nodes_for_manual_etcd_remove.is_empty():
        log.warning(f"Nodes {list(nodes_for_manual_etcd_remove.nodes.keys())} are considered as not active. "
                    "Full cleanup procedure cannot be performed. "
                    "Corresponding members will be removed from etcd manually.")
        etcd.remove_members(nodes_for_manual_etcd_remove)

    if not nodes_for_draining.is_empty():
        drain_nodes(nodes_for_draining, drain_timeout=drain_timeout, grace_period=grace_period)

    if is_add_or_remove_procedure and not active_nodes.is_empty():
        log.verbose(f"Resetting kubeadm on nodes {list(active_nodes.nodes.keys())} ...")
        result = active_nodes.sudo('sudo kubeadm reset -f')
        log.debug("Kubeadm successfully reset:\n%s" % result)

    if not active_nodes.is_empty():
        log.verbose(f"Cleaning nodes {list(active_nodes.nodes.keys())} ...")
        # bash semicolon mark will avoid script from exiting and will resume the execution
        result = active_nodes.sudo(
            'sudo kubeadm reset phase cleanup-node; '  # it is required to "cleanup-node" for all procedures
            'sudo systemctl stop kubelet; '
            'sudo rm -rf /etc/kubernetes/manifests /var/lib/kubelet/pki /var/lib/etcd /etc/kubernetes/patches; '
            'sudo mkdir -p /etc/kubernetes/manifests; ', warn=True)

        # Disabled initial prune for images prepull feature. Need analysis for possible negative impact.
        # result.update(cri.prune(active_nodes, all_implementations=True))

        log.debug(f"Nodes {list(active_nodes.nodes.keys())} cleaned up successfully:\n" + "%s" % result)

    if is_add_or_remove_procedure:
        return delete_nodes(group)


def drain_nodes(group, disable_eviction=False, drain_timeout=None, grace_period=None):
    log = group.cluster.log

    control_plane = group.cluster.nodes['control-plane'].get_final_nodes().get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list(provide_node_configs=True):
        if node["name"] in stdout:
            log.debug("Draining node %s..." % node["name"])
            control_plane.sudo(prepare_drain_command(node, group.cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                              group.cluster.globals, disable_eviction, group.cluster.nodes,
                                              drain_timeout, grace_period),
                        hide=False)
        else:
            log.warning("Node %s is not found in cluster and can't be drained" % node["name"])

    return control_plane.sudo("kubectl get nodes")


def delete_nodes(group):
    log = group.cluster.log

    control_plane = group.cluster.nodes['control-plane'].get_final_nodes().get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list(provide_node_configs=True):
        if node["name"] in stdout:
            log.debug("Deleting node %s from the cluster..." % node["name"])
            control_plane.sudo("kubectl delete node %s" % node["name"], hide=False)
        else:
            log.warning("Node %s is not found in cluster and can't be removed" % node["name"])

    return control_plane.sudo("kubectl get nodes")


def is_available_control_plane(control_plane):
    return not ("new_node" in control_plane["roles"] or "remove_node" in control_plane["roles"])


def install(group):
    log = group.cluster.log

    with RemoteExecutor(group.cluster):
        log.debug("Making systemd unit...")
        group.sudo('rm -rf /etc/systemd/system/kubelet*')
        for node in group.cluster.inventory["nodes"]:
            # perform only for current group members
            if node["connect_to"] in group.nodes.keys():
                template = Template(utils.read_internal('templates/kubelet.service.j2')).render(
                    hostname=node["name"])
                log.debug("Uploading to '%s'..." % node["connect_to"])
                node["connection"].put(io.StringIO(template + "\n"), '/etc/systemd/system/kubelet.service', sudo=True)
                node["connection"].sudo("chmod 644 /etc/systemd/system/kubelet.service")

        log.debug("\nReloading systemd daemon...")
        system.reload_systemctl(group)
        group.sudo('systemctl enable kubelet')

    return group.sudo('systemctl status kubelet', warn=True)


def join_other_control_planes(group):
    other_control_planes_group = group.get_ordered_members_list(provide_node_configs=True)[1:]

    join_dict = group.cluster.context["join_dict"]
    for node in other_control_planes_group:
        join_control_plane(group, node, join_dict)

    group.cluster.log.debug("Verifying installation...")
    first_control_plane = group.get_first_member(provide_node_configs=True)
    return first_control_plane['connection'].sudo("kubectl get pods --all-namespaces -o=wide")


def join_new_control_plane(group):
    join_dict = get_join_dict(group)
    for node in group.get_ordered_members_list(provide_node_configs=True):
        join_control_plane(group, node, join_dict)


def join_control_plane(group, node, join_dict):
    log = group.cluster.log

    join_config: dict = {
        'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'JoinConfiguration',
        'discovery': {
            'bootstrapToken': {
                'apiServerEndpoint': group.cluster.inventory["services"]["kubeadm"]['controlPlaneEndpoint'],
                'token': join_dict['token'],
                'caCertHashes': [
                    join_dict['discovery-token-ca-cert-hash']
                ]
            }
        },
        'controlPlane': {
            'certificateKey': join_dict['certificate-key'],
            'localAPIEndpoint': {
                'advertiseAddress': node['internal_address'],
            }
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in group.cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        join_config['patches'] = {'directory': '/etc/kubernetes/patches'}


    if group.cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        join_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    if 'worker' in node['roles']:
        join_config.setdefault('nodeRegistration', {})['taints'] = []

    configure_container_runtime(group.cluster, join_config)

    config = get_kubeadm_config(group.cluster.inventory) + "---\n" + yaml.dump(join_config, default_flow_style=False)

    utils.dump_file(group.cluster, config, 'join-config_%s.yaml' % node['name'])

    log.debug("Uploading init config to control-plane '%s'..." % node['name'])
    node['connection'].sudo("mkdir -p /etc/kubernetes")
    node['connection'].put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    create_kubeadm_patches_for_node(group.cluster, node)

    # copy admission config to control-plane
    admission.copy_pss(node['connection'])

    # ! ETCD on control-planes can't be initialized in async way, that is why it is necessary to disable async mode !
    log.debug('Joining control-plane \'%s\'...' % node['name'])

    # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
    # and only "else" branch remains
    if "v1.21" in group.cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        node['connection'].sudo("kubeadm join "
                            " --config=/etc/kubernetes/join-config.yaml"
                            " --ignore-preflight-errors='" + group.cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
                            " --v=5",
                            is_async=False, hide=False)

        log.debug("Patching apiServer bind-address for control-plane %s" % node['name'])

        with RemoteExecutor(group.cluster):
            node['connection'].sudo("sed -i 's/--bind-address=.*$/--bind-address=%s/' "
                                    "/etc/kubernetes/manifests/kube-apiserver.yaml" % node['internal_address'])
            node['connection'].sudo("systemctl restart kubelet")
            copy_admin_config(log, node['connection'])
    else:
        node['connection'].sudo("kubeadm join "
                           " --config=/etc/kubernetes/join-config.yaml "
                           " --ignore-preflight-errors='" + group.cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
                            " --v=5",
                            is_async=False, hide=False)
        with RemoteExecutor(group.cluster):
            node['connection'].sudo("systemctl restart kubelet")
            copy_admin_config(log, node['connection'])
       

    wait_for_any_pods(group.cluster, node['connection'], apply_filter=node['name'])


def copy_admin_config(log, nodes):
    log.debug("Setting up admin-config...")
    nodes.sudo("mkdir -p /root/.kube && sudo cp -f /etc/kubernetes/admin.conf /root/.kube/config")


def fetch_admin_config(cluster: KubernetesCluster) -> str:
    log = cluster.log

    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)
    log.debug(f"Downloading kubeconfig from node {first_control_plane['name']!r}...")

    kubeconfig = list(first_control_plane['connection'].sudo('cat /root/.kube/config').values())[0].stdout

    # Replace cluster FQDN with ip
    public_cluster_ip = cluster.inventory.get('public_cluster_ip')
    if public_cluster_ip:
        cluster_name = cluster.inventory['cluster_name']
        kubeconfig = kubeconfig.replace(cluster_name, public_cluster_ip)

    kubeconfig_filename = os.path.abspath("kubeconfig")
    with utils.open_external(kubeconfig_filename, 'w') as f:
        f.write(kubeconfig)

    cluster.log.debug(f"Kubeconfig saved to {kubeconfig_filename}")

    return kubeconfig_filename


def get_join_dict(group):
    first_control_plane = group.cluster.nodes["control-plane"].get_first_member(provide_node_configs=True)
    token_result = first_control_plane['connection'].sudo("kubeadm token create --print-join-command", hide=False)
    join_strings = list(token_result.values())[0].stdout.rstrip("\n")

    join_dict = {"worker_join_command": join_strings}
    join_array = join_strings[join_strings.find("--"):].split()
    for idx, _ in enumerate(join_array):
        current_string = join_array[idx]
        if "--" in current_string:
            join_dict[current_string.lstrip("--")] = join_array[idx + 1]

    cert_key_result = first_control_plane['connection'].sudo("kubeadm init phase upload-certs --upload-certs")
    cert_key = list(cert_key_result.values())[0].stdout.split("Using certificate key:\n")[1].rstrip("\n")
    join_dict["certificate-key"] = cert_key
    return join_dict


def init_first_control_plane(group):
    log = group.cluster.log

    first_control_plane = group.get_first_member(provide_node_configs=True)
    first_control_plane_group = first_control_plane["connection"]

    init_config: dict = {
        'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'InitConfiguration',
        'localAPIEndpoint': {
            'advertiseAddress': first_control_plane['internal_address']
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in group.cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        init_config['patches'] = {'directory': '/etc/kubernetes/patches'}

    if group.cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        init_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    if 'worker' in first_control_plane['roles']:
        init_config.setdefault('nodeRegistration', {})['taints'] = []

    configure_container_runtime(group.cluster, init_config)

    config = get_kubeadm_config(group.cluster.inventory) + "---\n" + yaml.dump(init_config, default_flow_style=False)

    utils.dump_file(group.cluster, config, 'init-config_%s.yaml' % first_control_plane['name'])

    log.debug("Uploading init config to initial control_plane...")
    first_control_plane_group.sudo("mkdir -p /etc/kubernetes")
    first_control_plane_group.put(io.StringIO(config), '/etc/kubernetes/init-config.yaml', sudo=True)

    # put control-plane patches
    create_kubeadm_patches_for_node(group.cluster, first_control_plane)

    # copy admission config to first control-plane
    first_control_plane_group.call(admission.copy_pss)

    log.debug("Initializing first control_plane...")
    result = first_control_plane_group.sudo("kubeadm init"
                                     " --upload-certs"
                                     " --config=/etc/kubernetes/init-config.yaml"
                                     " --ignore-preflight-errors='" + group.cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
                                     " --v=5",
                                     hide=False)

    copy_admin_config(log, first_control_plane_group)

    kubeconfig_filepath = fetch_admin_config(group.cluster)
    summary.schedule_report(group.cluster.context, summary.SummaryItem.KUBECONFIG, kubeconfig_filepath)

    # Invoke method from admission module for applying default PSS or privileged PSP if they are enabled
    first_control_plane_group.call(admission.apply_admission)

    # Preparing join_dict to init other nodes
    control_plane_lines = list(result.values())[0].stdout. \
                       split("You can now join any number of the control-plane")[1].splitlines()[2:5]
    worker_lines = list(result.values())[0].stdout. \
                       split("Then you can join any number of worker")[1].splitlines()[2:4]
    control_plane_join_command = " ".join([x.replace("\\", "").strip() for x in control_plane_lines])
    worker_join_command = " ".join([x.replace("\\", "").strip() for x in worker_lines])

    # TODO: Get rid of this code and use get_join_dict() method
    args = control_plane_join_command.split("--")
    join_dict = {}
    for arg in args:
        key_val = arg.split(" ")
        if len(key_val) > 1:
            join_dict[key_val[0].strip()] = key_val[1].strip()
    join_dict["worker_join_command"] = worker_join_command
    group.cluster.context["join_dict"] = join_dict

    wait_for_any_pods(group.cluster, first_control_plane_group, apply_filter=first_control_plane['name'])
    # refresh cluster installation status in cluster context
    is_cluster_installed(group.cluster)



def wait_for_any_pods(cluster, connection, apply_filter=None):
    if isinstance(cluster, NodeGroup):
        # cluster is a group, not a cluster
        cluster = cluster.cluster

    plugins.expect_pods(cluster, [
        'kube-apiserver',
        'kube-controller-manager',
        'kube-proxy',
        'kube-scheduler',
        'etcd'
    ], node=connection, apply_filter=apply_filter,
                        timeout=cluster.globals['pods']['expect']['kubernetes']['timeout'],
                        retries=cluster.globals['pods']['expect']['kubernetes']['retries'])


def wait_for_nodes(group):
    log = group.cluster.log

    first_control_plane = group.cluster.nodes["control-plane"].get_first_member()
    node_names = group.get_nodes_names()

    wait_conditions = {
        "Ready": "True",
        "NetworkUnavailable": "False"
    }
    if len(node_names) > 1:
        status_cmd = "kubectl get nodes %s -o jsonpath='{.items[*].status.conditions[?(@.type==\"%s\")].status}'"
    else:
        status_cmd = "kubectl get nodes %s -o jsonpath='{.status.conditions[?(@.type==\"%s\")].status}'"

    timeout = group.cluster.globals['nodes']['ready']['timeout']
    retries = group.cluster.globals['nodes']['ready']['retries']
    log.debug("Waiting for new kubernetes nodes to become ready")
    while retries > 0:
        correct_conditions = 0
        for condition, cond_value in wait_conditions.items():
            result = first_control_plane.sudo(status_cmd % (" ".join(node_names), condition))
            condition_results = list(result.values())[0].stdout.split(" ")
            correct_values = [value for value in condition_results if value == cond_value]
            if len(correct_values) == len(node_names):
                correct_conditions = correct_conditions + 1
                log.debug(f"Condition {condition} is {cond_value} for all nodes.")
            else:
                log.debug(f"Condition {condition} is not met, retrying")
                retries = retries - 1
                time.sleep(timeout)
                break

        if correct_conditions == len(wait_conditions):
            log.debug("All nodes are ready!")
            return

    raise Exception("Nodes did not become ready in the expected time")


def init_workers(group):
    join_dict = group.cluster.context.get("join_dict", get_join_dict(group))

    join_config = {
        'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'JoinConfiguration',
        'discovery': {
            'bootstrapToken': {
                'apiServerEndpoint': group.cluster.inventory["services"]["kubeadm"]['controlPlaneEndpoint'],
                'token': join_dict['token'],
                'caCertHashes': [
                    join_dict['discovery-token-ca-cert-hash']
                ]
            }
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in group.cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        join_config['patches'] = {'directory': '/etc/kubernetes/patches'}


    if group.cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        join_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    configure_container_runtime(group.cluster, join_config)

    config = yaml.dump(join_config, default_flow_style=False)

    utils.dump_file(group.cluster, config, 'join-config-workers.yaml')

    group.sudo("mkdir -p /etc/kubernetes")
    group.put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    for node in group.get_ordered_members_list(provide_node_configs=True):
        create_kubeadm_patches_for_node(group.cluster, node)

    group.cluster.log.debug('Joining workers...')

    return group.sudo(
            "kubeadm join --config=/etc/kubernetes/join-config.yaml"
            " --ignore-preflight-errors='" + group.cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
            " --v=5",
            is_async=False, hide=False)

def apply_labels(group):
    log = group.cluster.log

    log.debug("Applying additional labels for nodes")
    # TODO: Add "--overwrite-labels" switch
    # TODO: Add labels validation after applying
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            if "labels" not in node:
                log.verbose("No additional labels found for %s" % node['name'])
                continue
            log.verbose("Found additional labels for %s: %s" % (node['name'], node['labels']))
            for key, value in node["labels"].items():
                group.cluster.nodes["control-plane"].get_first_member() \
                    .sudo("kubectl label node %s %s=%s" % (node["name"], key, value))

    log.debug("Successfully applied additional labels")

    return group.cluster.nodes["control-plane"].get_first_member() \
        .sudo("kubectl get nodes --show-labels")
    # TODO: Add wait for pods on worker nodes


def apply_taints(group):
    log = group.cluster.log

    log.debug("Applying additional taints for nodes")
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            if "taints" not in node:
                log.verbose("No additional taints found for %s" % node['name'])
                continue
            log.verbose("Found additional taints for %s: %s" % (node['name'], node['taints']))
            for taint in node["taints"]:
                group.cluster.nodes["control-plane"].get_first_member() \
                    .sudo("kubectl taint node %s %s" % (node["name"], taint))

    log.debug("Successfully applied additional taints")

    return group.cluster.nodes["control-plane"].get_first_member() \
        .sudo("kubectl get nodes -o=jsonpath="
              "'{range .items[*]}{\"node: \"}{.metadata.name}{\"\\ntaints: \"}{.spec.taints}{\"\\n\"}'", hide=True)


def is_cluster_installed(cluster):
    cluster.log.verbose('Searching for already installed cluster...')
    try:
        result = cluster.nodes['control-plane'].sudo('kubectl cluster-info', warn=True, timeout=15)
        for conn, result in result.items():
            if 'is running at' in result.stdout:
                cluster.log.verbose('Detected running Kubernetes cluster on %s' % conn.host)
                for line in result.stdout.split("\n"):
                    if 'Kubernetes control plane' in line:
                        cluster.context['controlplain_uri'] = line.split('at ')[1]
                return True
    except Exception as e:
        cluster.log.verbose(e)
    cluster.context['controlplain_uri'] = None
    cluster.log.verbose('Failed to detect any Kubernetes cluster')
    return False


def get_kubeadm_config(inventory):
    kubeadm_kubelet = yaml.dump(inventory["services"]["kubeadm_kubelet"], default_flow_style=False)
    kubeadm = yaml.dump(inventory["services"]["kubeadm"], default_flow_style=False)
    return f'{kubeadm_kubelet}---\n{kubeadm}'

def upgrade_first_control_plane(version, upgrade_group, cluster, drain_timeout=None, grace_period=None):
    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)

    if not upgrade_group.has_node(first_control_plane['name']):
        cluster.log.debug("First control-plane \"%s\" upgrade is not required" % first_control_plane['name'])
        return

    cluster.log.debug("Upgrading first control-plane \"%s\"" % first_control_plane)

    # put control-plane patches
    create_kubeadm_patches_for_node(cluster, first_control_plane)
    
    # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
    # and only "else" branch remains
    if "v1.21" in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        flags = "-f --certificate-renewal=true --ignore-preflight-errors='%s'" % cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors']
    else:
        flags = "-f --certificate-renewal=true --ignore-preflight-errors='%s' --patches=/etc/kubernetes/patches" % cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors']

    if patch_kubeadm_configmap(first_control_plane, cluster):
        flags += " --config /tmp/kubeadm_config.yaml"

    disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)
    drain_cmd = prepare_drain_command(first_control_plane, version, cluster.globals, disable_eviction, cluster.nodes,
                                      drain_timeout, grace_period)
    first_control_plane['connection'].sudo(drain_cmd, is_async=False, hide=False)

    upgrade_cri_if_required(first_control_plane['connection'])

    first_control_plane['connection'].sudo(f"sudo kubeadm upgrade apply {version} {flags} && "
                                    f"sudo kubectl uncordon {first_control_plane['name']} && "
                                    f"sudo systemctl restart kubelet", is_async=False, hide=False)

    copy_admin_config(cluster.log, first_control_plane['connection'])

    expect_kubernetes_version(cluster, version, apply_filter=first_control_plane['name'])
    wait_for_any_pods(cluster, first_control_plane['connection'], apply_filter=first_control_plane['name'])
    exclude_node_from_upgrade_list(first_control_plane['connection'], first_control_plane['name'])


def upgrade_other_control_planes(version, upgrade_group, cluster, drain_timeout=None, grace_period=None):
    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)
    for node in cluster.nodes['control-plane'].get_ordered_members_list(provide_node_configs=True):
        if node['name'] != first_control_plane['name']:

            if not upgrade_group.has_node(node['name']):
                cluster.log.debug("Control-plane \"%s\" upgrade is not required" % node['name'])
                continue

            cluster.log.debug("Upgrading control-plane \"%s\"" % node['name'])

            # put control-plane patches
            create_kubeadm_patches_for_node(cluster, node)

            disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)
            drain_cmd = prepare_drain_command(node, version, cluster.globals, disable_eviction, cluster.nodes,
                                              drain_timeout, grace_period)
            node['connection'].sudo(drain_cmd, is_async=False, hide=False)

            upgrade_cri_if_required(node['connection'])

            # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
            # and only "else" branch remains
            if "v1.21" in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
                node['connection'].sudo(f"sudo kubeadm upgrade node --certificate-renewal=true && "
                                    f"sudo sed -i 's/--bind-address=.*$/--bind-address={node['internal_address']}/' "
                                    f"/etc/kubernetes/manifests/kube-apiserver.yaml && "
                                    f"sudo kubectl uncordon {node['name']} && "
                                    f"sudo systemctl restart kubelet", is_async=False, hide=False)
            else:
                node['connection'].sudo(f"sudo kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
                                    f"sudo kubectl uncordon {node['name']} && "
                                    f"sudo systemctl restart kubelet", is_async=False, hide=False)

            expect_kubernetes_version(cluster, version, apply_filter=node['name'])
            copy_admin_config(cluster.log, node['connection'])
            wait_for_any_pods(cluster, node['connection'], apply_filter=node['name'])
            exclude_node_from_upgrade_list(first_control_plane, node['name'])


def patch_kubeadm_configmap(first_control_plane, cluster):
    '''
    Checks and patches the Kubeadm configuration for compliance with the current imageRepository, audit log path
    and the corresponding version of the CoreDNS path to the image.
    '''
    # TODO: get rid of this method after k8s 1.21 support stop
    current_kubernetes_version = cluster.inventory['services']['kubeadm']['kubernetesVersion']
    kubeadm_config_map = first_control_plane["connection"].sudo("kubectl get cm -o yaml -n kube-system kubeadm-config") \
        .get_simple_out()
    ryaml = ruamel.yaml.YAML()
    config_map = ryaml.load(kubeadm_config_map)
    cluster_configuration_yaml = config_map["data"]["ClusterConfiguration"]
    cluster_config = ryaml.load(cluster_configuration_yaml)

    if not cluster_config.get("dns"):
        cluster_config["dns"] = {}

    updated_config = io.StringIO()

    cluster_config["apiServer"]["extraArgs"]["audit-log-path"] = \
        cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']['audit-log-path']

    if cluster.context.get('patch_image_repo', False):
        cluster_config["imageRepository"] = cluster_config["imageRepository"].replace('/k8s.gcr.io', '')

    new_image_repo_port = cluster.context.get('patch_image_repo_port', '')
    old_image_repo_port = cluster.context.get('old_image_repo_port', '')
    if new_image_repo_port and old_image_repo_port:
        cluster_config["imageRepository"] = cluster_config["imageRepository"].replace('/k8s.gcr.io', '')
        cluster_config["imageRepository"] = cluster_config["imageRepository"].replace(old_image_repo_port,
                                                                                      new_image_repo_port)

    if version_higher_or_equal(current_kubernetes_version, version_coredns_path_breakage):
        cluster_config['dns']['imageRepository'] = "%s/coredns" % cluster_config["imageRepository"]

    kubelet_config = first_control_plane["connection"].sudo("cat /var/lib/kubelet/config.yaml").get_simple_out()
    ryaml.dump(cluster_config, updated_config)
    result_config = kubelet_config + "---\n" + updated_config.getvalue()
    first_control_plane["connection"].put(io.StringIO(result_config), "/tmp/kubeadm_config.yaml", sudo=True)

    return True


def upgrade_workers(version, upgrade_group, cluster, drain_timeout=None, grace_period=None):
    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)
    for node in cluster.nodes.get('worker').exclude_group(cluster.nodes['control-plane']).get_ordered_members_list(
            provide_node_configs=True):

        if not upgrade_group.has_node(node['name']):
            cluster.log.debug("Worker \"%s\" upgrade is not required" % node['name'])
            continue

        cluster.log.debug("Upgrading worker \"%s\"" % node['name'])

        # put control-plane patches
        create_kubeadm_patches_for_node(cluster, node)

        disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)
        drain_cmd = prepare_drain_command(node, version, cluster.globals, disable_eviction, cluster.nodes,
                                          drain_timeout, grace_period)
        first_control_plane['connection'].sudo(drain_cmd, is_async=False, hide=False)

        upgrade_cri_if_required(node['connection'])

        # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
        # and only "else" branch remains
        if "v1.21" in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
            node['connection'].sudo("kubeadm upgrade node --certificate-renewal=true && "
                                "sudo systemctl restart kubelet")
        else:
           node['connection'].sudo("kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
                                "sudo systemctl restart kubelet")

        first_control_plane['connection'].sudo("kubectl uncordon %s" % node['name'], is_async=False, hide=False)

        expect_kubernetes_version(cluster, version, apply_filter=node['name'])
        # workers do not have system pods to wait for their start
        exclude_node_from_upgrade_list(first_control_plane, node['name'])


def prepare_drain_command(node, version: str, globals, disable_eviction: bool, nodes,
                          drain_timeout: int = None, grace_period: int = None):
    drain_globals = globals['nodes']['drain']
    if drain_timeout is None:
        drain_timeout = recalculate_proper_timeout(nodes, drain_globals['timeout'])
    if grace_period is None:
        grace_period = drain_globals['grace_period']
    drain_cmd = f"kubectl drain {node['name']} --force --ignore-daemonsets --delete-emptydir-data " \
                f"--timeout={drain_timeout}s --grace-period={grace_period}"
    if version and version >= "v1.18" and disable_eviction:
        drain_cmd += " --disable-eviction=true"
    return drain_cmd


def upgrade_cri_if_required(group):
    # currently it is invoked only for single node
    cluster = group.cluster
    log = cluster.log
    cri_impl = cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl in cluster.context["packages"]["upgrade_required"]:
        cri_packages = cluster.get_package_association_for_node(group.get_host(), cri_impl, 'package_name')

        log.debug(f"Installing {cri_packages}")
        packages.install(group, include=cri_packages)
        log.debug(f"Restarting all containers on nodes: {group.get_nodes_names()}")
        if cri_impl == "docker":
            group.sudo("docker container rm -f $(sudo docker container ls -q)", warn=True)
        else:
            group.sudo("crictl rm -fa", warn=True)
    else:
        log.debug(f"{cri_impl} upgrade is not required")


def verify_upgrade_versions(cluster):
    first_control_plane = cluster.nodes['control-plane'].get_first_member(provide_node_configs=True)
    upgrade_version = cluster.context["upgrade_version"]

    k8s_nodes_group = cluster.nodes["worker"].include_group(cluster.nodes['control-plane'])
    for node in k8s_nodes_group.get_ordered_members_list(provide_node_configs=True):
        cluster.log.debug(f"Verifying current k8s version for node {node['name']}")
        result = first_control_plane['connection'].sudo("kubectl get nodes "
                                                 f"{node['name']}"
                                                 " -o custom-columns='VERSION:.status.nodeInfo.kubeletVersion' "
                                                 "| grep -vw ^VERSION ")
        curr_version = list(result.values())[0].stdout
        test_version_upgrade_possible(curr_version, upgrade_version, skip_equal=True)


def verify_target_version(target_version):
    test_version(target_version)

    pos = target_version.rfind(".")
    target_version = target_version[:pos]
    globals_yml = static.GLOBALS
    if target_version not in globals_yml["kubernetes_versions"]:
        raise Exception("ERROR! Specified target Kubernetes version '%s' - cannot be installed!" % target_version)
    if not globals_yml["kubernetes_versions"].get(target_version, {}).get("supported", False):
        message = "\033[91mWarning! Specified target Kubernetes version '%s' - is not supported!\033[0m" % target_version
        print(message)
        return message
    return ""


def expect_kubernetes_version(cluster, version, timeout=None, retries=None, node=None, apply_filter=None):
    if timeout is None:
        timeout = cluster.globals['nodes']['expect']['kubernetes_version']['timeout']
    if retries is None:
        retries = cluster.globals['nodes']['expect']['kubernetes_version']['retries']

    cluster.log.debug("Expecting Kubernetes version %s" % version)
    cluster.log.debug("Max expectation time: %ss" % (timeout * retries))

    cluster.log.debug("Waiting for nodes...\n")

    if node is None:
        node = cluster.nodes['control-plane'].get_first_member()

    command = 'kubectl get nodes -o=wide'
    if apply_filter is not None:
        command += ' | grep -w %s' % apply_filter

    while retries > 0:
        result = node.sudo(command, warn=True)
        stdout = list(result.values())[0].stdout
        cluster.log.verbose(stdout)
        nodes_version_correct = True
        for stdout_line in iter(stdout.splitlines()):
            if version not in stdout_line:
                nodes_version_correct = False
                cluster.log.verbose("Invalid version detected: %s\n" % stdout_line)

        if nodes_version_correct:
            cluster.log.debug("Nodes have correct Kubernetes version = %s" % version)
            cluster.log.debug(result)
            return
        else:
            retries -= 1
            cluster.log.debug("Some nodes have invalid Kubernetes version... (%ss left)" % (retries * timeout), result)
            time.sleep(timeout)

    raise Exception('In the expected time, the nodes did not receive correct Kubernetes version')


def test_version(version: Union[list, str]):
    version_list: list = version
    # catch version without "v" at the first symbol
    if isinstance(version, str):
        if not version.startswith('v'):
            raise Exception('Version \"%s\" do not have \"v\" as first symbol, '
                            'expected version pattern is \"v1.NN.NN\"' % version)
        version_list = version.replace('v', '').split('.')
    # catch invalid version 'v1.16'
    if len(version_list) != 3:
        raise Exception('Version \"%s\" has invalid amount of numbers, '
                        'expected version pattern is \"v1.NN.NN\"' % version)

    # parse str to int and catch invalid symbols in version number
    for i, value in enumerate(version_list):
        try:
            # whitespace required because python's int() ignores them
            version_list[i] = int(value.replace(' ', '.'))
        except ValueError:
            raise Exception('Version \"%s\" contains invalid symbols, '
                            'expected version pattern is \"v1.NN.NN\"' % version) from None
    return version_list


def test_version_upgrade_possible(old, new, skip_equal=False):
    versions_unchanged = {
        'old': old.strip(),
        'new': new.strip()
    }
    versions: Dict[str, List[int]] = {}

    for v_type, version in versions_unchanged.items():
        versions[v_type] = test_version(version)

    # test new is greater than old
    if tuple(versions['old']) > tuple(versions['new']):
        raise Exception(ERROR_DOWNGRADE % (versions_unchanged['old'], versions_unchanged['new']))

    # test new is the same as old
    if tuple(versions['old']) == tuple(versions['new']) and not skip_equal:
        raise Exception(ERROR_SAME % (versions_unchanged['old'], versions_unchanged['new']))

    # test major step is not greater than 1
    if versions['new'][0] - versions['old'][0] > 1:
        raise Exception(ERROR_MAJOR_RANGE_EXCEEDED % (versions_unchanged['old'], versions_unchanged['new']))

    # test minor step is not greater than 1
    if versions['new'][1] - versions['old'][1] > 1:
        raise Exception(ERROR_MINOR_RANGE_EXCEEDED % (versions_unchanged['old'], versions_unchanged['new']))


def recalculate_proper_timeout(nodes, timeout):
    try:
        amount_str = nodes['control-plane'].get_first_member().sudo('kubectl get pods -A | wc -l').get_simple_out()
        return timeout * int(amount_str)
    except Exception:
        return timeout * 10 * nodes['all'].nodes_amount()


def configure_container_runtime(cluster, kubeadm_config):
    if cluster.inventory['services']['cri']['containerRuntime'] == "containerd":
        if 'nodeRegistration' not in kubeadm_config:
            kubeadm_config['nodeRegistration'] = {}
        if 'kubeletExtraArgs' not in kubeadm_config['nodeRegistration']:
            kubeadm_config['nodeRegistration']['kubeletExtraArgs'] = {}

        kubeadm_config['nodeRegistration']['criSocket'] = '/var/run/containerd/containerd.sock'
        kubeadm_config['nodeRegistration']['kubeletExtraArgs']['container-runtime'] = 'remote'
        kubeadm_config['nodeRegistration']['kubeletExtraArgs']['container-runtime-endpoint'] = \
            'unix:///run/containerd/containerd.sock'


def exclude_node_from_upgrade_list(first_control_plane, node_name):
    if isinstance(first_control_plane, dict):
        first_control_plane = first_control_plane['connection']
    return first_control_plane.sudo('sed -i \'/%s/d\' /etc/kubernetes/nodes-k8s-versions.txt' % node_name, warn=True)


def autodetect_non_upgraded_nodes(cluster, future_version) -> List[str]:
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    try:
        nodes_list_result = first_control_plane.sudo('[ ! -f /etc/kubernetes/nodes-k8s-versions.txt ] && '
                                              'sudo kubectl get nodes -o custom-columns=\''
                                              'VERSION:.status.nodeInfo.kubeletVersion,'
                                              'NAME:.metadata.name,'
                                              'STATUS:.status.conditions[-1].type\' '
                                              '| sed -n \'1!p\' | tr -s \' \' '
                                              '| sed \'1 i\\# This file contains a cached list of nodes and versions '
                                              'required to continue the Kubernetes upgrade procedure if it fails. '
                                              'If all the nodes are completely updated or you manually fixed the '
                                              'problem that occurred during the upgrade, you can delete it.\' '
                                              '| sudo tee /etc/kubernetes/nodes-k8s-versions.txt; '
                                              'sudo cat /etc/kubernetes/nodes-k8s-versions.txt') \
            .get_simple_out()
        cluster.log.verbose("Remote response with nodes description:\n%s" % nodes_list_result)
    except Exception as e:
        cluster.log.warn("Failed to detect cluster status before upgrade. All nodes will be scheduled for upgrade.")
        cluster.log.verbose(e)
        return cluster.nodes['all'].get_nodes_names()

    detected_nodes_lines = nodes_list_result.splitlines()

    if not detected_nodes_lines:
        raise Exception('Remote result did not returned any lines containing node info')

    upgrade_list = []
    for line in detected_nodes_lines:
        line = line.strip()

        # comes from nodes-k8s-versions.txt content as a comment symbol
        if line[0] == '#':
            continue
        version, node_name, status = line.split(' ')
        if version != future_version:
            cluster.log.verbose("Node \"%s\" has version \"%s\" and scheduled for upgrade." % (node_name, version))
            upgrade_list.append(node_name)
        elif status != 'Ready':
            cluster.log.verbose("Node \"%s\" is not ready and scheduled for upgrade." % node_name)
            upgrade_list.append(node_name)
        else:
            cluster.log.verbose("Node \"%s\" already upgraded." % node_name)

    return upgrade_list


def get_group_for_upgrade(cluster, ignore_cache=False):

    if cluster.context.get('upgrade_group') and not ignore_cache:
        return cluster.context['upgrade_group']

    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    if cluster.procedure_inventory.get('upgrade_nodes'):
        nodes_for_upgrade = []
        for node in cluster.procedure_inventory['upgrade_nodes']:
            if isinstance(node, str):
                node_name = node
            else:
                node_name = node['name']
            nodes_for_upgrade.append(node_name)
            cluster.log.verbose("Node \"%s\" manually scheduled for upgrade." % node_name)
            cluster.nodes['control-plane'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt', warn=True)
    else:
        nodes_for_upgrade = autodetect_non_upgraded_nodes(cluster, version)

    upgrade_group = cluster.make_group_from_nodes(nodes_for_upgrade)
    cluster.context['upgrade_group'] = upgrade_group

    return cluster.context['upgrade_group']


def images_grouped_prepull(group: NodeGroup, group_size: int = None):
    """
    Prepull kubeadm images on group, separated on sub-groups with certain group size. Separation required to avoid high
    load on images repository server, when using large clusters.
    :param group: NodeGroup where prepull should be performed.
    :param group_size: integer number of nodes per group. Will be automatically used from procedure_yaml or globals, if not set.
    :return: String results from all nodes in presented group.
    """

    cluster = group.cluster
    log = cluster.log

    if not group_size:
        group_size = cluster.procedure_inventory.get('prepull_group_size')

    if not group_size:
        log.verbose("Group size is not set in procedure inventory, a default one will be used")
        group_size = cluster.globals.get('prepull_group_size')

    nodes = group.get_ordered_members_list()

    # group_size should be greater than 0
    if len(nodes) != 0 and len(nodes) < group_size:
        group_size = len(nodes)

    groups_amount = math.ceil(len(nodes) / group_size)

    log.verbose("Nodes amount: %s\nGroup size: %s\nGroups amount: %s" % (len(nodes), group_size, groups_amount))
    with RemoteExecutor(cluster) as exe:
        for group_i in range(groups_amount):
            log.verbose('Prepulling images for group #%s...' % group_i)
            # RemoteExecutor used for future cases, when some nodes will require another/additional actions for prepull
            for node_i in range(group_i*group_size, (group_i*group_size)+group_size):
                if node_i < len(nodes):
                    images_prepull(nodes[node_i])

    return exe.get_last_results_str()


def images_prepull(group: NodeGroup):
    """
    Prepull kubeadm images on group.
    :param group: NodeGroup where prepull should be performed.
    :return: NodeGroupResult from all nodes in presented group.
    """

    config = get_kubeadm_config(group.cluster.inventory)
    group.put(io.StringIO(config), '/etc/kubernetes/prepull-config.yaml', sudo=True)

    return group.sudo("kubeadm config images pull --config=/etc/kubernetes/prepull-config.yaml")


def schedule_running_nodes_report(cluster: KubernetesCluster):
    summary.schedule_delayed_report(cluster, exec_running_nodes_report)


def exec_running_nodes_report(cluster: KubernetesCluster):
    nodes_description = get_nodes_description(cluster)
    actual_roles = get_actual_roles(nodes_description)
    nodes_conditions = get_nodes_conditions(nodes_description)
    nodes_names = actual_roles.keys()
    for role in ('control-plane', 'worker'):
        members = 0
        ready = 0
        for name in nodes_names:
            if role in actual_roles[name]:
                members += 1
                conditions = nodes_conditions[name]
                if conditions.get('Ready', {}).get('status') == 'True' \
                        and conditions.get('NetworkUnavailable', {}).get('status') == 'False':
                    ready += 1

        property = summary.SummaryItem.CONTROL_PLANES if role == 'control-plane' else summary.SummaryItem.WORKERS
        value = f'{ready}/{members}'
        summary.schedule_report(cluster.context, property, value)


def get_nodes_description_cmd() -> str:
    return 'kubectl get node -o yaml'


def get_nodes_description(cluster: KubernetesCluster) -> dict:
    cmd = get_nodes_description_cmd()
    result = cluster.nodes['control-plane'].get_final_nodes().get_any_member().sudo(cmd)
    cluster.log.verbose(result)
    return yaml.safe_load(list(result.values())[0].stdout)


def get_actual_roles(nodes_description: dict) -> Dict[str, List[str]]:
    result = {}
    for node_description in nodes_description['items']:
        node_name = node_description['metadata']['name']
        labels = node_description['metadata']['labels']
        result[node_name] = []
        # TODO check label accordingly to Kubernetes version
        if 'node-role.kubernetes.io/master' in labels or 'node-role.kubernetes.io/control-plane' in labels:
            result[node_name].append('control-plane')
        if 'node-role.kubernetes.io/worker' in labels:
            result[node_name].append('worker')

    return result


def get_nodes_conditions(nodes_description: dict) -> Dict[str, Dict[str, dict]]:
    result = {}
    for node_description in nodes_description['items']:
        node_name = node_description['metadata']['name']
        conditions_by_type = {}
        result[node_name] = conditions_by_type
        for condition in node_description['status']['conditions']:
            conditions_by_type[condition['type']] = condition

    return result

# function to get dictionary of flags to be patched for a given control plane item and a given node
def get_patched_flags_for_control_plane_item(inventory, control_plane_item, node):
    flags = {}

    for n in inventory['services']['kubeadm_patches'][control_plane_item]:
        if n.get('groups') is not None and list(set(node['roles']) & set(n['groups'])):
            if n.get('patch') is not None:
                for arg, value in n['patch'].items():
                    flags[arg] = value
        if n.get('nodes') is not None and node['name'] in n['nodes']:
            if n.get('patch') is not None:
                for arg, value in n['patch'].items():
                    flags[arg] = value

    # we always set binding-address to the node's internal address for apiServer
    if control_plane_item == 'apiServer' and 'control-plane' in node['roles']:
        flags['bind-address'] = node['internal_address']

    return flags

# function to create kubeadm patches and put them to a node
def create_kubeadm_patches_for_node(cluster, node):
    cluster.log.verbose(f"Create and upload kubeadm patches to %s..." % node['name'])
    node['connection'].sudo('sudo rm -rf /etc/kubernetes/patches ; sudo mkdir -p /etc/kubernetes/patches', warn=True)

    # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
    if "v1.21" in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        # do nothing, patches are supported since v1.22
        return

    control_plane_patch_files = {
        'apiServer' : 'kube-apiserver+json.json',
        'etcd' : 'etcd+json.json',
        'controllerManager' : 'kube-controller-manager+json.json',
        'scheduler' : 'kube-scheduler_json.json',
        'kubelet' : 'kubeletconfiguration.yaml'
    }

    # read patches content from inventory and upload patch files to a node
    for control_plane_item in cluster.inventory['services']['kubeadm_patches']:
        patched_flags = get_patched_flags_for_control_plane_item(cluster.inventory, control_plane_item, node)
        if patched_flags:
            if control_plane_item == 'kubelet':
                template_filename = 'templates/patches/kubelet.yaml.j2'
            else:
                template_filename = 'templates/patches/control-plane-pod.json.j2'

            control_plane_patch = Template(utils.read_internal(template_filename)).render(flags=patched_flags)
            node['connection'].put(io.StringIO(control_plane_patch + "\n"), '/etc/kubernetes/patches/' +
                                 control_plane_patch_files[control_plane_item], sudo=True)
            node['connection'].sudo('chmod 644 /etc/kubernetes/patches/' +
                                 control_plane_patch_files[control_plane_item])

    return


