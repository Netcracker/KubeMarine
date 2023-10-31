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
import uuid
from contextlib import contextmanager
from copy import deepcopy
from typing import List, Dict, Tuple, Iterator, Any, Optional

import yaml
from jinja2 import Template
import ipaddress

from kubemarine import system, plugins, admission, etcd, packages
from kubemarine.core import utils, static, summary, log, errors
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import Token
from kubemarine.core.group import (
    NodeGroup, AbstractGroup, DeferredGroup,
    NodeConfig, RunnersGroupResult, RunResult, CollectorCallback
)
from kubemarine.core.errors import KME
from kubemarine.cri import containerd

ERROR_DOWNGRADE='Kubernetes old version \"%s\" is greater than new one \"%s\"'
ERROR_SAME='Kubernetes old version \"%s\" is the same as new one \"%s\"'
ERROR_MAJOR_RANGE_EXCEEDED='Major version \"%s\" rises to new \"%s\" more than one'
ERROR_MINOR_RANGE_EXCEEDED='Minor version \"%s\" rises to new \"%s\" more than one'


def add_node_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') != 'add_node':
        return inventory

    # adding role "new_node" for all specified new nodes and putting these nodes to all "nodes" list
    for new_node in cluster.procedure_inventory.get("nodes", []):
        # deepcopy is necessary, otherwise role append will happen in procedure_inventory too
        node = deepcopy(new_node)
        node["roles"].append("add_node")
        inventory["nodes"].append(node)

    # If "vrrp_ips" section is ever supported when adding node,
    # It will be necessary to more accurately install and reconfigure the keepalived on existing nodes.

    # if "vrrp_ips" in cluster.procedure_inventory:
    #     utils.merge_vrrp_ips(cluster.procedure_inventory, inventory)

    return inventory


def remove_node_enrichment(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') != 'remove_node':
        return inventory

    # adding role "remove_node" for all specified nodes
    node_names_to_remove = [node['name'] for node in cluster.procedure_inventory.get("nodes", [])]
    for node_remove in node_names_to_remove:
        for i, node in enumerate(inventory['nodes']):
            # Inventory is not compiled at this step.
            # Expecting that the names are not jinja, or the same jinja expressions.
            if node['name'] == node_remove:
                node['roles'].append('remove_node')
                break
        else:
            raise Exception(f"Failed to find node to remove {node_remove} among existing nodes")

    return inventory


def enrich_upgrade_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') == 'upgrade':
        cluster.context['initial_kubernetes_version'] = inventory['services']['kubeadm']['kubernetesVersion']

        cluster.log.info(
            '------------------------------------------\nUPGRADING KUBERNETES %s ⭢ %s\n------------------------------------------' % (
            cluster.context['initial_kubernetes_version'], cluster.context['upgrade_version']))

    return generic_upgrade_inventory(cluster, inventory)


def upgrade_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    return generic_upgrade_inventory(cluster, inventory)


def generic_upgrade_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    upgrade_version = cluster.context.get("upgrade_version")
    inventory.setdefault("services", {}).setdefault("kubeadm", {})['kubernetesVersion'] = upgrade_version
    return inventory


def enrich_restore_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get("initial_procedure") != "restore":
        return inventory

    logger = cluster.log
    kubernetes_descriptor = cluster.context['backup_descriptor'].setdefault('kubernetes', {})
    initial_kubernetes_version = get_initial_kubernetes_version(inventory)
    backup_kubernetes_version = kubernetes_descriptor.get('version')
    if not backup_kubernetes_version:
        logger.warning("Not possible to verify Kubernetes version, as descriptor does not contain 'kubernetes.version'")
        backup_kubernetes_version = initial_kubernetes_version

    if backup_kubernetes_version != initial_kubernetes_version:
        logger.warning('Installed kubernetes version does not match version from backup')
        verify_allowed_version(backup_kubernetes_version)

    kubernetes_descriptor['version'] = backup_kubernetes_version
    return restore_finalize_inventory(cluster, inventory)


def restore_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    if cluster.context.get("initial_procedure") != "restore":
        return inventory

    target_kubernetes_version = cluster.context['backup_descriptor']['kubernetes']['version']
    inventory.setdefault("services", {}).setdefault("kubeadm", {})['kubernetesVersion'] = target_kubernetes_version
    return inventory


def enrich_inventory(inventory: dict, _: KubernetesCluster) -> dict:
    kubeadm = inventory['services']['kubeadm']
    kubeadm['dns'].setdefault('imageRepository', f"{kubeadm['imageRepository']}/coredns")

    enriched_certsans = []

    for node in inventory["nodes"]:
        if ('balancer' in node['roles'] or 'control-plane' in node['roles']) and 'remove_node' not in node['roles']:
            enriched_certsans.extend([node['name'], node['internal_address']])
            if node.get('address') is not None:
                enriched_certsans.append(node['address'])

    # The VRRP IP may be actually unused, but let's add it because it is probably specified to be used in the future.
    for item in inventory["vrrp_ips"]:
        enriched_certsans.append(item['ip'])
        if item.get("floating_ip"):
            enriched_certsans.append(item["floating_ip"])

    if inventory.get("public_cluster_ip"):
        enriched_certsans.append(inventory["public_cluster_ip"])

    certsans = inventory["services"]["kubeadm"]['apiServer']['certSANs']

    # do not overwrite apiServer.certSANs, but append - may be user specified something already there?
    for name in enriched_certsans:
        if name not in certsans:
            certsans.append(name)

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
            
    # Validate the provided podSubnet IP address
    pod_subnet = inventory.get('services', {}).get('kubeadm', {}).get('networking', {}).get('podSubnet')
    try:
        ip_network = ipaddress.ip_network(pod_subnet)
        if ip_network.version not in [4, 6]:
            raise ValueError(f"Invalid podSubnet IP address: {pod_subnet}")
    except ValueError:
        raise ValueError(f"Invalid podSubnet IP address: {pod_subnet}")

    # Validate the provided serviceSubnet IP address
    service_subnet = inventory.get('services', {}).get('kubeadm', {}).get('networking', {}).get('serviceSubnet')
    try:
        ip_network = ipaddress.ip_network(service_subnet)
        if ip_network.version not in [4, 6]:
            raise ValueError(f"Invalid serviceSubnet IP address: {service_subnet}")
    except ValueError:
        raise ValueError(f"Invalid serviceSubnet IP address: {service_subnet}")

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


def reset_installation_env(group: NodeGroup) -> Optional[RunnersGroupResult]:
    log = group.cluster.log

    log.debug("Cleaning up previous installation...")

    cluster: KubernetesCluster = group.cluster

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
        log.warning(f"Nodes {nodes_for_manual_etcd_remove.get_hosts()} are considered as not active. "
                    "Full cleanup procedure cannot be performed. "
                    "Corresponding members will be removed from etcd manually.")
        etcd.remove_members(nodes_for_manual_etcd_remove)

    if not nodes_for_draining.is_empty():
        drain_nodes(nodes_for_draining, drain_timeout=drain_timeout, grace_period=grace_period)

    if is_add_or_remove_procedure and not active_nodes.is_empty():
        log.verbose(f"Resetting kubeadm on nodes {active_nodes.get_hosts()} ...")
        result = active_nodes.sudo('sudo kubeadm reset -f')
        log.debug("Kubeadm successfully reset:\n%s" % result)

    if not active_nodes.is_empty():
        log.verbose(f"Cleaning nodes {active_nodes.get_hosts()} ...")
        # bash semicolon mark will avoid script from exiting and will resume the execution
        result = active_nodes.sudo(
            'sudo kubeadm reset phase cleanup-node; '  # it is required to "cleanup-node" for all procedures
            'sudo systemctl stop kubelet; '
            'sudo rm -rf /etc/kubernetes/manifests /var/lib/kubelet/pki /var/lib/etcd /etc/kubernetes/patches; '
            'sudo mkdir -p /etc/kubernetes/manifests; ', warn=True)

        # Disabled initial prune for images prepull feature. Need analysis for possible negative impact.
        # result.update(cri.prune(active_nodes, all_implementations=True))

        log.debug(f"Nodes {active_nodes.get_hosts()} cleaned up successfully:\n" + "%s" % result)

    if is_add_or_remove_procedure:
        return delete_nodes(group)

    return None


def drain_nodes(group: NodeGroup, disable_eviction: bool = False,
                drain_timeout: int = None, grace_period: int = None) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    control_plane = cluster.nodes['control-plane'].get_final_nodes().get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list():
        node_name = node.get_node_name()
        if node_name in stdout:
            log.debug("Draining node %s..." % node_name)
            drain_cmd = prepare_drain_command(
                cluster, node_name,
                disable_eviction=disable_eviction, drain_timeout=drain_timeout, grace_period=grace_period)
            control_plane.sudo(drain_cmd, hide=False)
        else:
            log.warning("Node %s is not found in cluster and can't be drained" % node_name)

    return control_plane.sudo("kubectl get nodes")


def delete_nodes(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    control_plane = cluster.nodes['control-plane'].get_final_nodes().get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list():
        node_name = node.get_node_name()
        if node_name in stdout:
            log.debug("Deleting node %s from the cluster..." % node_name)
            control_plane.sudo("kubectl delete node %s" % node_name, hide=False)
        else:
            log.warning("Node %s is not found in cluster and can't be removed" % node_name)

    return control_plane.sudo("kubectl get nodes")


def install(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    with group.new_executor() as exe:
        log.debug("Making systemd unit...")
        for node in exe.group.get_ordered_members_list():
            node.sudo('rm -rf /etc/systemd/system/kubelet*')
            template = Template(utils.read_internal('templates/kubelet.service.j2')).render(
                hostname=node.get_node_name())
            log.debug("Uploading to '%s'..." % node.get_host())
            node.put(io.StringIO(template + "\n"), '/etc/systemd/system/kubelet.service', sudo=True)
            node.sudo("chmod 600 /etc/systemd/system/kubelet.service")

        log.debug("\nReloading systemd daemon...")
        system.reload_systemctl(exe.group)
        exe.group.sudo('systemctl enable kubelet')

    return group.sudo('systemctl status kubelet', warn=True)


def join_other_control_planes(group: NodeGroup) -> RunnersGroupResult:
    other_control_planes_group = group.get_ordered_members_list()[1:]

    join_dict = group.cluster.context["join_dict"]
    for node in other_control_planes_group:
        join_control_plane(group.cluster, node, join_dict)

    group.cluster.log.debug("Verifying installation...")
    first_control_plane = group.get_first_member()
    return first_control_plane.sudo("kubectl get pods --all-namespaces -o=wide")


def join_new_control_plane(group: NodeGroup) -> None:
    join_dict = get_join_dict(group)
    for node in group.get_ordered_members_list():
        join_control_plane(group.cluster, node, join_dict)


def join_control_plane(cluster: KubernetesCluster, node: NodeGroup, join_dict: dict) -> None:
    log = cluster.log
    node_config = node.get_config()
    node_name = node.get_node_name()
    defer = node.new_defer()

    join_config: dict = {
        'apiVersion': cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'JoinConfiguration',
        'discovery': {
            'bootstrapToken': {
                'apiServerEndpoint': cluster.inventory["services"]["kubeadm"]['controlPlaneEndpoint'],
                'token': join_dict['token'],
                'caCertHashes': [
                    join_dict['discovery-token-ca-cert-hash']
                ]
            }
        },
        'controlPlane': {
            'certificateKey': join_dict['certificate-key'],
            'localAPIEndpoint': {
                'advertiseAddress': node_config['internal_address'],
            }
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        join_config['patches'] = {'directory': '/etc/kubernetes/patches'}

    if cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        join_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    if 'worker' in node_config['roles']:
        join_config.setdefault('nodeRegistration', {})['taints'] = []

    configure_container_runtime(cluster, join_config)

    config = get_kubeadm_config(cluster.inventory) + "---\n" + yaml.dump(join_config, default_flow_style=False)

    utils.dump_file(cluster, config, 'join-config_%s.yaml' % node_name)

    log.debug("Uploading init config to control-plane '%s'..." % node_name)
    node.sudo("mkdir -p /etc/kubernetes")
    node.put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    create_kubeadm_patches_for_node(cluster, node)

    # copy admission config to control-plane
    admission.copy_pss(node)

    # put audit-policy.yaml
    prepare_audit_policy(node)

    # ! ETCD on control-planes can't be initialized in async way, that is why it is necessary to disable async mode !
    log.debug('Joining control-plane \'%s\'...' % node_name)

    node.sudo(
        "kubeadm join "
        " --config=/etc/kubernetes/join-config.yaml "
        " --ignore-preflight-errors='" + cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
        " --v=5",
        hide=False)
    defer.sudo("systemctl restart kubelet")
    copy_admin_config(log, defer)
    defer.flush()

    wait_for_any_pods(cluster, node, apply_filter=node_name)


@contextmanager
def local_admin_config(nodes: NodeGroup) -> Iterator[str]:
    temp_filepath = "/tmp/%s" % uuid.uuid4().hex

    cluster_name = nodes.cluster.inventory['cluster_name']

    try:
        with nodes.new_executor() as exe:
            for defer in exe.group.get_ordered_members_list():
                internal_address = defer.get_config()['internal_address']
                if type(ipaddress.ip_address(internal_address)) is ipaddress.IPv6Address:
                    internal_address = f"[{internal_address}]"

                defer.sudo(
                    f"cp /root/.kube/config {temp_filepath} "
                    f"&& sudo sed -i 's/{cluster_name}/{internal_address}/' {temp_filepath}")
        yield temp_filepath
    finally:
        nodes.sudo(f'rm -f {temp_filepath}')


def copy_admin_config(logger: log.EnhancedLogger, nodes: AbstractGroup[RunResult]) -> None:
    logger.debug("Setting up admin-config...")
    command = "mkdir -p /root/.kube && sudo cp -f /etc/kubernetes/admin.conf /root/.kube/config"
    nodes.sudo(command)


def fetch_admin_config(cluster: KubernetesCluster) -> str:
    log = cluster.log

    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    log.debug(f"Downloading kubeconfig from node {first_control_plane.get_node_name()!r}...")

    kubeconfig = list(first_control_plane.sudo('cat /root/.kube/config').values())[0].stdout

    # Replace cluster FQDN with ip
    public_cluster_ip = cluster.inventory.get('public_cluster_ip')
    if public_cluster_ip:
        if type(ipaddress.ip_address(public_cluster_ip)) is ipaddress.IPv6Address:
            public_cluster_ip = f"[{public_cluster_ip}]"
        cluster_name = cluster.inventory['cluster_name']
        kubeconfig = kubeconfig.replace(cluster_name, public_cluster_ip)

    kubeconfig_filename = os.path.abspath("kubeconfig")
    utils.dump_file(cluster.context, kubeconfig, kubeconfig_filename, dump_location=False)
    cluster.log.debug(f"Kubeconfig saved to {kubeconfig_filename}")

    return kubeconfig_filename


def get_join_dict(group: NodeGroup) -> dict:
    cluster: KubernetesCluster = group.cluster
    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    token_result = first_control_plane.sudo("kubeadm token create --print-join-command", hide=False)
    join_strings = list(token_result.values())[0].stdout.rstrip("\n")

    join_dict = {"worker_join_command": join_strings}
    join_array = join_strings[join_strings.find("--"):].split()
    for idx, _ in enumerate(join_array):
        current_string = join_array[idx]
        if "--" in current_string:
            join_dict[current_string.lstrip("--")] = join_array[idx + 1]

    cert_key_result = first_control_plane.sudo("kubeadm init phase upload-certs --upload-certs")
    cert_key = list(cert_key_result.values())[0].stdout.split("Using certificate key:\n")[1].rstrip("\n")
    join_dict["certificate-key"] = cert_key
    return join_dict


def init_first_control_plane(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    first_control_plane = group.get_first_member()
    node_config = first_control_plane.get_config()
    node_name = first_control_plane.get_node_name()

    init_config: dict = {
        'apiVersion': cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'InitConfiguration',
        'localAPIEndpoint': {
            'advertiseAddress': node_config['internal_address']
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        init_config['patches'] = {'directory': '/etc/kubernetes/patches'}

    if cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        init_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    if 'worker' in node_config['roles']:
        init_config.setdefault('nodeRegistration', {})['taints'] = []

    configure_container_runtime(cluster, init_config)

    config = get_kubeadm_config(cluster.inventory) + "---\n" + yaml.dump(init_config, default_flow_style=False)

    utils.dump_file(cluster, config, 'init-config_%s.yaml' % node_name)

    log.debug("Uploading init config to initial control_plane...")
    first_control_plane.sudo("mkdir -p /etc/kubernetes")
    first_control_plane.put(io.StringIO(config), '/etc/kubernetes/init-config.yaml', sudo=True)

    # put control-plane patches
    create_kubeadm_patches_for_node(cluster, first_control_plane)

    # copy admission config to first control-plane
    first_control_plane.call(admission.copy_pss)

    # put audit-policy.yaml
    prepare_audit_policy(first_control_plane)

    log.debug("Initializing first control_plane...")
    result = first_control_plane.sudo(
        "kubeadm init"
        " --upload-certs"
        " --config=/etc/kubernetes/init-config.yaml"
        " --ignore-preflight-errors='" + cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
        " --v=5",
        hide=False)

    copy_admin_config(log, first_control_plane)

    kubeconfig_filepath = fetch_admin_config(cluster)
    summary.schedule_report(cluster.context, summary.SummaryItem.KUBECONFIG, kubeconfig_filepath)

    # Invoke method from admission module for applying default PSS or privileged PSP if they are enabled
    first_control_plane.call(admission.apply_admission)

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
    cluster.context["join_dict"] = join_dict

    wait_for_any_pods(cluster, first_control_plane, apply_filter=node_name)
    # refresh cluster installation status in cluster context
    is_cluster_installed(cluster)


def wait_for_any_pods(cluster: KubernetesCluster, connection: NodeGroup, apply_filter: str = None) -> None:
    plugins.expect_pods(cluster, [
        'kube-apiserver',
        'kube-controller-manager',
        'kube-proxy',
        'kube-scheduler',
        'etcd'
    ], node=connection, apply_filter=apply_filter,
                        timeout=cluster.inventory['globals']['expect']['pods']['kubernetes']['timeout'],
                        retries=cluster.inventory['globals']['expect']['pods']['kubernetes']['retries'])


def wait_uncordon(node: NodeGroup) -> None:
    cluster = node.cluster
    timeout_config = cluster.inventory['globals']['expect']['pods']['kubernetes']
    # This forces to use local API server and waits till it is up.
    with local_admin_config(node) as kubeconfig:
        utils.wait_command_successful(node, f"kubectl --kubeconfig {kubeconfig} uncordon {node.get_node_name()}",
                                      hide=False,
                                      timeout=timeout_config['timeout'],
                                      retries=timeout_config['retries'])


def wait_for_nodes(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    first_control_plane = cluster.nodes["control-plane"].get_first_member()
    node_names = group.get_nodes_names()

    wait_conditions = {
        "Ready": "True",
        "NetworkUnavailable": "False"
    }
    if len(node_names) > 1:
        status_cmd = "kubectl get nodes %s -o jsonpath='{.items[*].status.conditions[?(@.type==\"%s\")].status}'"
    else:
        status_cmd = "kubectl get nodes %s -o jsonpath='{.status.conditions[?(@.type==\"%s\")].status}'"

    timeout = int(cluster.inventory['globals']['nodes']['ready']['timeout'])
    retries = int(cluster.inventory['globals']['nodes']['ready']['retries'])
    log.debug("Waiting for new kubernetes nodes to become ready, %s retries every %s seconds" % (retries, timeout))
    while retries > 0:
        correct_conditions = 0
        for condition, cond_value in wait_conditions.items():
            result = first_control_plane.sudo(status_cmd % (" ".join(node_names), condition), warn=True)
            node_result = list(result.values())[0]
            if node_result.failed:
                log.debug(f"kubectl exited with non-zero exit code. Haproxy or kube-apiserver are not yet started?")
                log.verbose(node_result)
                break
            condition_results = node_result.stdout.split(" ")
            correct_values = [value for value in condition_results if value == cond_value]
            if len(correct_values) == len(node_names):
                correct_conditions = correct_conditions + 1
                log.debug(f"Condition {condition} is {cond_value} for all nodes.")
            else:
                log.debug(f"Condition {condition} is not met, retrying")
                break

        if correct_conditions == len(wait_conditions):
            log.debug("All nodes are ready!")
            return
        else:
            retries = retries - 1
            time.sleep(timeout)

    raise Exception("Nodes did not become ready in the expected time, %s retries every %s seconds. Try to increase node.ready.retries parameter in globals: https://github.com/Netcracker/KubeMarine/blob/main/documentation/Installation.md#globals" % (retries, timeout))


def init_workers(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    join_dict = cluster.context.get("join_dict", get_join_dict(group))

    join_config = {
        'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'JoinConfiguration',
        'discovery': {
            'bootstrapToken': {
                'apiServerEndpoint': cluster.inventory["services"]["kubeadm"]['controlPlaneEndpoint'],
                'token': join_dict['token'],
                'caCertHashes': [
                    join_dict['discovery-token-ca-cert-hash']
                ]
            }
        }
    }

    # TODO: when k8s v1.21 is excluded from Kubemarine, patches should be added to InitConfiguration unconditionally
    if "v1.21" not in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
        join_config['patches'] = {'directory': '/etc/kubernetes/patches'}

    if cluster.inventory['services']['kubeadm']['controllerManager']['extraArgs'].get(
            'external-cloud-volume-plugin'):
        join_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    configure_container_runtime(cluster, join_config)

    config = yaml.dump(join_config, default_flow_style=False)

    utils.dump_file(cluster, config, 'join-config-workers.yaml')

    group.sudo("mkdir -p /etc/kubernetes")
    group.put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    for node in group.get_ordered_members_list():
        create_kubeadm_patches_for_node(cluster, node)

    cluster.log.debug('Joining workers...')

    for node in group.get_ordered_members_list():
        node.sudo(
            "kubeadm join --config=/etc/kubernetes/join-config.yaml"
            " --ignore-preflight-errors='" + cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
            " --v=5",
            hide=False)


def apply_labels(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    log.debug("Applying additional labels for nodes")
    # TODO: Add "--overwrite-labels" switch
    # TODO: Add labels validation after applying
    control_plane = cluster.nodes["control-plane"].get_first_member()
    with control_plane.new_executor() as exe:
        for node in group.get_ordered_members_configs_list():
            if "labels" not in node:
                log.verbose("No additional labels found for %s" % node['name'])
                continue
            log.verbose("Found additional labels for %s: %s" % (node['name'], node['labels']))
            for key, value in node["labels"].items():
                exe.group.sudo("kubectl label node %s %s=%s" % (node["name"], key, value))

    log.debug("Successfully applied additional labels")

    return control_plane.sudo("kubectl get nodes --show-labels")
    # TODO: Add wait for pods on worker nodes


def apply_taints(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    log.debug("Applying additional taints for nodes")
    control_plane = cluster.nodes["control-plane"].get_first_member()
    with control_plane.new_executor() as exe:
        for node in group.get_ordered_members_configs_list():
            if "taints" not in node:
                log.verbose("No additional taints found for %s" % node['name'])
                continue
            log.verbose("Found additional taints for %s: %s" % (node['name'], node['taints']))
            for taint in node["taints"]:
                exe.group.sudo("kubectl taint node %s %s" % (node["name"], taint))

    log.debug("Successfully applied additional taints")

    return control_plane.sudo(
        "kubectl get nodes -o=jsonpath="
        "'{range .items[*]}{\"node: \"}{.metadata.name}{\"\\ntaints: \"}{.spec.taints}{\"\\n\"}'")


def is_cluster_installed(cluster: KubernetesCluster) -> bool:
    cluster.log.verbose('Searching for already installed cluster...')
    try:
        results = cluster.nodes['control-plane'].sudo('kubectl cluster-info', warn=True, timeout=15)
        for host, result in results.items():
            if 'is running at' in result.stdout:
                cluster.log.verbose('Detected running Kubernetes cluster on %s' % host)
                for line in result.stdout.split("\n"):
                    if 'Kubernetes control plane' in line:
                        cluster.context['controlplain_uri'] = line.split('at ')[1]
                return True
    except Exception as e:
        cluster.log.verbose(e)
    cluster.context['controlplain_uri'] = None
    cluster.log.verbose('Failed to detect any Kubernetes cluster')
    return False


def get_kubeadm_config(inventory: dict) -> str:
    kubeadm_kubelet = yaml.dump(inventory["services"]["kubeadm_kubelet"], default_flow_style=False)
    kubeadm = yaml.dump(inventory["services"]["kubeadm"], default_flow_style=False)
    return f'{kubeadm_kubelet}---\n{kubeadm}'


def upgrade_first_control_plane(upgrade_group: NodeGroup, cluster: KubernetesCluster, **drain_kwargs: Any) -> None:
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    node_name = first_control_plane.get_node_name()

    if not upgrade_group.has_node(node_name):
        cluster.log.debug("First control-plane \"%s\" upgrade is not required" % node_name)
        return

    cluster.log.debug("Upgrading first control-plane \"%s\"" % node_name)

    # put control-plane patches
    create_kubeadm_patches_for_node(cluster, first_control_plane)

    flags = "-f --certificate-renewal=true --ignore-preflight-errors='%s' --patches=/etc/kubernetes/patches" % cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors']

    drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
    first_control_plane.sudo(drain_cmd, hide=False)

    upgrade_cri_if_required(first_control_plane)
    fix_flag_kubelet(first_control_plane)

    first_control_plane.sudo(
        f"sudo kubeadm upgrade apply {version} {flags} && "
        f"sudo kubectl uncordon {node_name} && "
        f"sudo systemctl restart kubelet", hide=False)

    copy_admin_config(cluster.log, first_control_plane)

    expect_kubernetes_version(cluster, version, apply_filter=node_name)
    wait_for_any_pods(cluster, first_control_plane, apply_filter=node_name)
    exclude_node_from_upgrade_list(first_control_plane, node_name)


def upgrade_other_control_planes(upgrade_group: NodeGroup, cluster: KubernetesCluster, **drain_kwargs: Any) -> None:
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    first_control_plane = cluster.nodes['control-plane'].get_first_member()

    for node in cluster.nodes['control-plane'].get_ordered_members_list():
        node_name = node.get_node_name()
        if node_name != first_control_plane.get_node_name():

            if not upgrade_group.has_node(node_name):
                cluster.log.debug("Control-plane \"%s\" upgrade is not required" % node_name)
                continue

            cluster.log.debug("Upgrading control-plane \"%s\"" % node_name)

            # put control-plane patches
            create_kubeadm_patches_for_node(cluster, node)

            drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
            node.sudo(drain_cmd, hide=False)

            upgrade_cri_if_required(node)
            fix_flag_kubelet(node)

            node.sudo(
                f"sudo kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
                f"sudo kubectl uncordon {node_name} && "
                f"sudo systemctl restart kubelet",
                hide=False)

            expect_kubernetes_version(cluster, version, apply_filter=node_name)
            copy_admin_config(cluster.log, node)
            wait_for_any_pods(cluster, node, apply_filter=node_name)
            exclude_node_from_upgrade_list(first_control_plane, node_name)


def upgrade_workers(upgrade_group: NodeGroup, cluster: KubernetesCluster, **drain_kwargs: Any) -> None:
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    first_control_plane = cluster.nodes['control-plane'].get_first_member()

    for node in cluster.nodes['worker'].exclude_group(cluster.nodes['control-plane'])\
            .get_ordered_members_list():
        node_name = node.get_node_name()

        if not upgrade_group.has_node(node_name):
            cluster.log.debug("Worker \"%s\" upgrade is not required" % node_name)
            continue

        cluster.log.debug("Upgrading worker \"%s\"" % node_name)

        # put control-plane patches
        create_kubeadm_patches_for_node(cluster, node)

        drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
        first_control_plane.sudo(drain_cmd, hide=False)

        upgrade_cri_if_required(node)
        fix_flag_kubelet(node)

        node.sudo(
            "kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
            "sudo systemctl restart kubelet")

        first_control_plane.sudo("kubectl uncordon %s" % node_name, hide=False)

        expect_kubernetes_version(cluster, version, apply_filter=node_name)
        # workers do not have system pods to wait for their start
        exclude_node_from_upgrade_list(first_control_plane, node_name)


def prepare_drain_command(cluster: KubernetesCluster, node_name: str,
                          *,
                          disable_eviction: bool = False,
                          drain_timeout: int = None, grace_period: int = None) -> str:
    drain_globals = static.GLOBALS['nodes']['drain']
    if drain_timeout is None:
        drain_timeout = recalculate_proper_timeout(cluster, drain_globals['timeout'])

    if grace_period is None:
        grace_period = drain_globals['grace_period']

    drain_cmd = f"kubectl drain {node_name} --force --ignore-daemonsets --delete-emptydir-data " \
                f"--timeout={drain_timeout}s --grace-period={grace_period}"
    if disable_eviction:
        drain_cmd += " --disable-eviction=true"
    return drain_cmd


def upgrade_cri_if_required(group: NodeGroup) -> None:
    # currently it is invoked only for single node
    cluster: KubernetesCluster = group.cluster
    log = cluster.log
    cri_impl = cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl in cluster.context["upgrade"]["required"]['packages']:
        cri_packages = cluster.get_package_association_for_node(group.get_host(), cri_impl, 'package_name')

        log.debug(f"Installing {cri_packages} on node: {group.get_node_name()}")
        packages.install(group, include=cri_packages)
        log.debug(f"Restarting all containers on node: {group.get_node_name()}")
        if cri_impl == "docker":
            group.sudo("docker container rm -f $(sudo docker container ls -q)", warn=True)
        else:
            group.sudo("crictl rm -fa", warn=True)
    else:
        log.debug(f"{cri_impl!r} package upgrade is not required")

    # upgrade of sandbox_image is currently not supported for migrate_kubemarine
    if cri_impl == 'containerd' and cluster.context["upgrade"]["required"].get('containerdConfig', False):
        containerd.configure_containerd(group)
    else:
        log.debug(f"{cri_impl!r} configuration upgrade is not required")


def verify_upgrade_versions(cluster: KubernetesCluster) -> None:
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    upgrade_version = cluster.context["upgrade_version"]

    k8s_nodes_group = cluster.nodes["worker"].include_group(cluster.nodes['control-plane'])
    for node in k8s_nodes_group.get_ordered_members_list():
        cluster.log.debug(f"Verifying current k8s version for node {node.get_node_name()}")
        result = first_control_plane.sudo("kubectl get nodes "
                                          f"{node.get_node_name()}"
                                          " -o custom-columns='VERSION:.status.nodeInfo.kubeletVersion' "
                                          "| grep -vw ^VERSION ")
        curr_version = list(result.values())[0].stdout
        test_version_upgrade_possible(curr_version, upgrade_version, skip_equal=True)


def get_initial_kubernetes_version(inventory: dict) -> str:
    kubernetes_version: str
    if inventory.get("services", {}).get("kubeadm", {}).get("kubernetesVersion") is not None:
        kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
    else:
        kubernetes_version = static.DEFAULTS['services']['kubeadm']['kubernetesVersion']

    return kubernetes_version


def verify_initial_version(inventory: dict, _: KubernetesCluster) -> dict:
    version = get_initial_kubernetes_version(inventory)
    verify_allowed_version(version)
    return inventory


def verify_allowed_version(version: str) -> None:
    allowed_versions = static.KUBERNETES_VERSIONS['compatibility_map'].keys()
    if version not in allowed_versions:
        raise errors.KME('KME0008',
                         version=version,
                         allowed_versions=', '.join(map(repr, allowed_versions)))


def verify_supported_version(target_version: str, logger: log.EnhancedLogger) -> None:
    verify_allowed_version(target_version)
    minor_version = utils.minor_version(target_version)
    supported_versions = static.KUBERNETES_VERSIONS['kubernetes_versions']
    if not supported_versions.get(minor_version, {}).get("supported", False):
        logger.warning(f"Specified target Kubernetes version {target_version!r} - is not supported!")


def expect_kubernetes_version(cluster: KubernetesCluster, version: str,
                              timeout: int = None, retries: int = None,
                              node: NodeGroup = None, apply_filter: str = None) -> None:
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


def test_version_upgrade_possible(old: str, new: str, skip_equal: bool = False) -> None:
    versions_unchanged = {
        'old': old.strip(),
        'new': new.strip()
    }
    versions: Dict[str, Tuple[int, int, int]] = {}

    for v_type, version in versions_unchanged.items():
        versions[v_type] = utils.version_key(version)

    # test new is greater than old
    if versions['old'] > versions['new']:
        raise Exception(ERROR_DOWNGRADE % (versions_unchanged['old'], versions_unchanged['new']))

    # test new is the same as old
    if versions['old'] == versions['new'] and not skip_equal:
        raise Exception(ERROR_SAME % (versions_unchanged['old'], versions_unchanged['new']))

    # test major step is not greater than 1
    if versions['new'][0] - versions['old'][0] > 1:
        raise Exception(ERROR_MAJOR_RANGE_EXCEEDED % (versions_unchanged['old'], versions_unchanged['new']))

    # test minor step is not greater than 1
    if versions['new'][1] - versions['old'][1] > 1:
        raise Exception(ERROR_MINOR_RANGE_EXCEEDED % (versions_unchanged['old'], versions_unchanged['new']))


def recalculate_proper_timeout(cluster: KubernetesCluster, timeout: int) -> int:
    try:
        amount_str = cluster.nodes['control-plane'].get_first_member().sudo('kubectl get pods -A | wc -l').get_simple_out()
        return timeout * int(amount_str)
    except Exception:
        return timeout * 10 * cluster.nodes['all'].nodes_amount()


def configure_container_runtime(cluster: KubernetesCluster, kubeadm_config: dict) -> None:
    if cluster.inventory['services']['cri']['containerRuntime'] == "containerd":
        if 'nodeRegistration' not in kubeadm_config:
            kubeadm_config['nodeRegistration'] = {}
        if 'kubeletExtraArgs' not in kubeadm_config['nodeRegistration']:
            kubeadm_config['nodeRegistration']['kubeletExtraArgs'] = {}

        kubeadm_config['nodeRegistration']['criSocket'] = '/var/run/containerd/containerd.sock'

        minor_version = int(cluster.inventory["services"]["kubeadm"]["kubernetesVersion"].split('.')[1])
        if minor_version < 27:
            kubeadm_config['nodeRegistration']['kubeletExtraArgs']['container-runtime'] = 'remote'

        kubeadm_config['nodeRegistration']['kubeletExtraArgs']['container-runtime-endpoint'] = \
            'unix:///run/containerd/containerd.sock'


def exclude_node_from_upgrade_list(first_control_plane: NodeGroup, node_name: str) -> None:
    first_control_plane.sudo('sed -i \'/%s/d\' /etc/kubernetes/nodes-k8s-versions.txt' % node_name, warn=True)


def autodetect_non_upgraded_nodes(cluster: KubernetesCluster, future_version: str) -> List[str]:
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
        cluster.log.warning("Failed to detect cluster status before upgrade. All nodes will be scheduled for upgrade.")
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


def get_group_for_upgrade(cluster: KubernetesCluster) -> NodeGroup:
    upgrade_group: Optional[NodeGroup] = cluster.context.get('upgrade_group')
    if upgrade_group is not None:
        return upgrade_group

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

    return upgrade_group


def images_grouped_prepull(group: NodeGroup, group_size: int = None) -> RunnersGroupResult:
    """
    Prepull kubeadm images on group, separated on sub-groups with certain group size. Separation required to avoid high
    load on images repository server, when using large clusters.
    :param group: NodeGroup where prepull should be performed.
    :param group_size: integer number of nodes per group. Will be automatically used from procedure_yaml or globals, if not set.
    :return: String results from all nodes in presented group.
    """

    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    if group_size is None:
        group_size = cluster.procedure_inventory.get('prepull_group_size')

    if group_size is None:
        log.verbose("Group size is not set in procedure inventory, a default one will be used")
        group_size = cluster.globals['prepull_group_size']

    nodes_amount = group.nodes_amount()

    # group_size should be greater than 0
    if nodes_amount != 0 and nodes_amount < group_size:
        group_size = nodes_amount

    groups_amount = math.ceil(nodes_amount / group_size)

    log.verbose("Nodes amount: %s\nGroup size: %s\nGroups amount: %s" % (nodes_amount, group_size, groups_amount))
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        nodes = exe.group.get_ordered_members_list()
        for group_i in range(groups_amount):
            log.verbose('Prepulling images for group #%s...' % group_i)
            # RemoteExecutor used for future cases, when some nodes will require another/additional actions for prepull
            for node_i in range(group_i*group_size, (group_i*group_size)+group_size):
                if node_i < nodes_amount:
                    images_prepull(nodes[node_i], collector=collector)

    return collector.result


def images_prepull(group: DeferredGroup, collector: CollectorCallback) -> Token:
    """
    Prepull kubeadm images on group.

    :param group: NodeGroup where prepull should be performed.
    :param collector: CollectorCallback instance
    :return: NodeGroupResult from all nodes in presented group.
    """

    config = get_kubeadm_config(group.cluster.inventory)
    kubeadm_init: dict = {
        'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
        'kind': 'InitConfiguration',
    }

    configure_container_runtime(group.cluster, kubeadm_init)
    config = f'{config}---\n{yaml.dump(kubeadm_init, default_flow_style=False)}'

    group.put(io.StringIO(config), '/etc/kubernetes/prepull-config.yaml', sudo=True)

    return group.sudo("kubeadm config images pull --config=/etc/kubernetes/prepull-config.yaml",
                      callback=collector)


def schedule_running_nodes_report(cluster: KubernetesCluster) -> None:
    summary.schedule_delayed_report(cluster, exec_running_nodes_report)


def exec_running_nodes_report(cluster: KubernetesCluster) -> None:
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
    data: dict = yaml.safe_load(list(result.values())[0].stdout)
    return data


def get_actual_roles(nodes_description: dict) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
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
        conditions_by_type: Dict[str, dict] = {}
        result[node_name] = conditions_by_type
        for condition in node_description['status']['conditions']:
            conditions_by_type[condition['type']] = condition

    return result


# function to get dictionary of flags to be patched for a given control plane item and a given node
def get_patched_flags_for_control_plane_item(inventory: dict, control_plane_item: str, node: NodeConfig) -> Dict[str, str]:
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
def create_kubeadm_patches_for_node(cluster: KubernetesCluster, node: NodeGroup) -> None:
    cluster.log.verbose(f"Create and upload kubeadm patches to %s..." % node.get_node_name())
    node.sudo('sudo rm -rf /etc/kubernetes/patches ; sudo mkdir -p /etc/kubernetes/patches', warn=True)

    control_plane_patch_files = {
        'apiServer' : 'kube-apiserver+json.json',
        'etcd' : 'etcd+json.json',
        'controllerManager' : 'kube-controller-manager+json.json',
        'scheduler' : 'kube-scheduler_json.json',
        'kubelet' : 'kubeletconfiguration.yaml'
    }

    # read patches content from inventory and upload patch files to a node
    node_config = node.get_config()
    for control_plane_item in cluster.inventory['services']['kubeadm_patches']:
        patched_flags = get_patched_flags_for_control_plane_item(cluster.inventory, control_plane_item, node_config)
        if patched_flags:
            if control_plane_item == 'kubelet':
                template_filename = 'templates/patches/kubelet.yaml.j2'
            else:
                template_filename = 'templates/patches/control-plane-pod.json.j2'

            control_plane_patch = Template(utils.read_internal(template_filename)).render(flags=patched_flags)
            patch_file = '/etc/kubernetes/patches/' + control_plane_patch_files[control_plane_item]
            node.put(io.StringIO(control_plane_patch + "\n"), patch_file, sudo=True)
            node.sudo(f'chmod 644 {patch_file}')


def fix_flag_kubelet(group: NodeGroup) -> bool:
    kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
    cluster = group.cluster
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    sandbox_image = containerd.get_sandbox_image(cluster.inventory['services']['cri'])
    infra_image_flag = f"--pod-infra-container-image={sandbox_image}"
    container_runtime_flag = '--container-runtime=remote'

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            node.sudo(f"cat {kubeadm_flags_file}", callback=collector)

    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            kubeadm_flags = collector.result[node.get_host()].stdout
            updated_kubeadm_flags = kubeadm_flags
            if utils.version_key(version) >= utils.version_key("v1.27.0"):
                # remove the deprecated kubelet flag for versions starting from 1.27.0
                updated_kubeadm_flags = updated_kubeadm_flags.replace(container_runtime_flag, '')

            if infra_image_flag not in updated_kubeadm_flags:
                # patch --pod-infra-container-image with target sandbox_image
                updated_kubeadm_flags = config_changer(updated_kubeadm_flags, infra_image_flag)

            if kubeadm_flags != updated_kubeadm_flags:
                cluster.log.debug(f"Patching {kubeadm_flags_file} on {node.get_node_name()} node...")
                node.put(io.StringIO(updated_kubeadm_flags), kubeadm_flags_file, backup=True, sudo=True)

    # If file is changed on at least one node, last results will be not empty
    return len(exe.get_last_results()) > 0


def config_changer(config: str, word: str) -> str:
    equal_pos = word.find("=") + 1
    param_begin_pos = config.find(word[:equal_pos])
    if param_begin_pos != -1:
        param_end_pos = config[param_begin_pos:].find(" ")
        if param_end_pos == -1:
            return config[:param_begin_pos] + word + "\""
        return config[:param_begin_pos] + word + config[param_end_pos + param_begin_pos:]
    else:
        param_end_pos = config.rfind("\"")
        return config[:param_end_pos] + " " + word[:] + "\""


def prepare_audit_policy(group: NodeGroup) -> None:
    """
    Prepare audit-policy.yaml and all necessary directories.
    """
    cluster: KubernetesCluster = group.cluster
    api_server_extra_args = cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']
    audit_log_dir = os.path.dirname(api_server_extra_args['audit-log-path'])
    audit_file_name = api_server_extra_args['audit-policy-file']
    audit_policy_dir = os.path.dirname(audit_file_name)
    group.sudo(f"mkdir -p {audit_log_dir} && sudo mkdir -p {audit_policy_dir}")

    cluster.log.debug("Configure audit cluster policy")
    policy_config = cluster.inventory['services']['audit']['cluster_policy']
    policy_config_file = yaml.dump(policy_config)
    utils.dump_file(cluster, policy_config_file, 'audit-policy.yaml')
    # upload rules on cluster
    group.put(io.StringIO(policy_config_file), audit_file_name, sudo=True, backup=True)
