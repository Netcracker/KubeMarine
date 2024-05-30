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
from contextlib import contextmanager
from typing import List, Dict, Iterator, Any, Optional

import yaml
from jinja2 import Template
from ordered_set import OrderedSet

from kubemarine import system, admission, etcd, packages, jinja, sysctl
from kubemarine.core import utils, static, summary, log, errors
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.executor import Token
from kubemarine.core.group import NodeGroup, DeferredGroup, RunnersGroupResult, CollectorCallback
from kubemarine.core.errors import KME
from kubemarine.core.yaml_merger import default_merger
from kubemarine.cri import containerd
from kubemarine.kubernetes import components

ERROR_DOWNGRADE='Kubernetes old version \"%s\" is greater than new one \"%s\"'
ERROR_SAME='Kubernetes old version \"%s\" is the same as new one \"%s\"'
ERROR_MAJOR_RANGE_EXCEEDED='Major version \"%s\" rises to new \"%s\" more than one'
ERROR_MINOR_RANGE_EXCEEDED='Minor version \"%s\" rises to new \"%s\" more than one'
ERROR_NOT_LATEST_PATCH='New version \"%s\" is not the latest supported patch version \"%s\"'

ERROR_KUBELET_PATCH_NOT_KUBERNETES_NODE = "%s patch can be uploaded only to control-plane or worker nodes"
ERROR_CONTROL_PLANE_PATCH_NOT_CONTROL_PLANE_NODE = "%s patch can be uploaded only to control-plane nodes"

ERROR_UPGRADE_UNEXPECTED_PROPERTY='Unexpected %s properties in the procedure inventory for upgrade.'

ERROR_AMBIGUOUS_CONNTRACK_MAX = "Detected ambiguous 'net.netfilter.nf_conntrack_max' value: {values}"


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def enrich_upgrade_inventory(cluster: KubernetesCluster) -> None:
    procedure_inventory = cluster.procedure_inventory
    allowed_properties = {
        'upgrade_plan', 'upgrade_nodes', 'disable-eviction', 'prepull_group_size', 'grace_period', 'drain_timeout'
    }
    allowed_properties.update(procedure_inventory['upgrade_plan'])
    unexpected_properties = set(procedure_inventory) - allowed_properties
    if unexpected_properties:
        raise Exception(ERROR_UPGRADE_UNEXPECTED_PROPERTY % (', '.join(map(repr, unexpected_properties)),))

    upgrade_version = get_procedure_upgrade_version(cluster)
    cluster.inventory.setdefault("services", {}).setdefault("kubeadm", {})['kubernetesVersion'] = upgrade_version


@enrichment(EnrichmentStage.PROCEDURE, procedures=['upgrade'])
def verify_upgrade_inventory(cluster: KubernetesCluster) -> None:
    initial_kubernetes_version = get_kubernetes_version(cluster.previous_inventory)
    upgrade_version = get_kubernetes_version(cluster.inventory)

    test_version_upgrade_possible(initial_kubernetes_version, upgrade_version)

    cluster.log.info(
        '------------------------------------------\nUPGRADING KUBERNETES %s ⭢ %s\n------------------------------------------' % (
        initial_kubernetes_version, upgrade_version))

    dump_directory = utils.get_dump_directory(cluster.context)
    if jinja.is_template(get_procedure_upgrade_version(cluster)) and os.path.exists(dump_directory):
        os.rename(dump_directory, os.path.join(os.path.dirname(dump_directory), upgrade_version))
        cluster.context['dump_subdir'] = upgrade_version


@enrichment(EnrichmentStage.PROCEDURE, procedures=['restore'])
def enrich_restore_inventory(cluster: KubernetesCluster) -> None:
    logger = cluster.log
    inventory = cluster.inventory
    backup_version = cluster.context['backup_descriptor'].get('kubernetes', {}).get('version')
    if not backup_version:
        logger.warning("Not possible to verify Kubernetes version, as descriptor does not contain 'kubernetes.version'")
        return

    installed_version = get_kubernetes_version(inventory)
    if backup_version != installed_version and not jinja.is_template(installed_version):
        logger.warning(f'Installed kubernetes version {installed_version} '
                       f'does not match version from backup {backup_version}')

    inventory.setdefault("services", {}).setdefault("kubeadm", {})['kubernetesVersion'] = backup_version


@enrichment(EnrichmentStage.PROCEDURE, procedures=['reconfigure'])
def enrich_reconfigure_inventory(cluster: KubernetesCluster) -> None:
    kubeadm_sections = utils.subdict_yaml(
        cluster.procedure_inventory.get('services', {}),
        ['kubeadm', 'kubeadm_kubelet', 'kubeadm_kube-proxy', 'kubeadm_patches'])

    if kubeadm_sections:
        default_merger.merge(cluster.inventory.setdefault('services', {}), utils.deepcopy_yaml(kubeadm_sections))


@enrichment(EnrichmentStage.ALL)
def verify_roles(cluster: KubernetesCluster) -> None:
    control_plane_roles = ['control-plane']
    if cluster.context['initial_procedure'] == 'do':
        control_plane_roles = ['control-plane', 'master']

    if cluster.make_group_from_roles(control_plane_roles).is_empty():
        raise KME("KME0004")


@enrichment(EnrichmentStage.FULL)
def enrich_inventory(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory
    kubeadm = inventory['services']['kubeadm']
    kubeadm['dns'].setdefault('imageRepository', f"{kubeadm['imageRepository']}/coredns")

    enriched_certsans = []

    for node in inventory["nodes"]:
        if 'balancer' in node['roles'] or 'control-plane' in node['roles']:
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

    certsans = kubeadm['apiServer']['certSANs']

    # do not overwrite apiServer.certSANs, but append - may be user specified something already there?
    for name in enriched_certsans:
        if name not in certsans:
            certsans.append(name)

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
            if "labels" not in node:
                node["labels"] = {}
            node["labels"]["node-role.kubernetes.io/worker"] = "worker"

    # Validate the provided podSubnet and serviceSubnet IP addresses
    for subnet in ('podSubnet', 'serviceSubnet'):
        utils.isipv(kubeadm['networking'][subnet], [4, 6])

    # validate nodes in kubeadm_patches (groups are validated with JSON schema)
    for control_plane_item, patches in inventory["services"]["kubeadm_patches"].items():
        for patch in patches:
            if 'nodes' not in patch:
                continue

            for node in cluster.get_nodes_by_names(patch['nodes']):
                if control_plane_item == 'kubelet' and 'control-plane' not in node['roles'] and 'worker' not in node['roles']:
                    raise Exception(ERROR_KUBELET_PATCH_NOT_KUBERNETES_NODE % control_plane_item)
                if control_plane_item != 'kubelet' and ('control-plane' not in node['roles']):
                    raise Exception(ERROR_CONTROL_PLANE_PATCH_NOT_CONTROL_PLANE_NODE % control_plane_item)

    # check ignorePreflightErrors value and add mandatory errors from defaults.yaml if they're absent
    default_preflight_errors = static.DEFAULTS["services"]["kubeadm_flags"]["ignorePreflightErrors"].split(",")
    preflight_errors = inventory["services"]["kubeadm_flags"]["ignorePreflightErrors"].split(",")

    preflight_errors.extend(default_preflight_errors)
    inventory["services"]["kubeadm_flags"]["ignorePreflightErrors"] = ",".join(set(preflight_errors))

    enrich_kube_proxy(cluster)


def enrich_kube_proxy(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory

    # override kubeadm_kube-proxy.conntrack.min with sysctl.net.netfilter.nf_conntrack_max
    # since they define the same kernel variable
    kubernetes_nodes = cluster.make_group_from_roles(['control-plane', 'worker'])
    conntrack_max_values = OrderedSet(
        sysctl.get_parameter(cluster, node, 'net.netfilter.nf_conntrack_max')
        for node in kubernetes_nodes.get_ordered_members_list()
    )

    if len(conntrack_max_values) > 1:
        raise Exception(ERROR_AMBIGUOUS_CONNTRACK_MAX.format(
            values='{' + ', '.join(map(repr, conntrack_max_values)) + '}'))

    conntrack_max = next(iter(conntrack_max_values), None)
    if components.kube_proxy_overwrites_higher_system_values(cluster) and conntrack_max is not None:
        inventory["services"]["kubeadm_kube-proxy"]["conntrack"]["min"] = conntrack_max
    else:
        inventory["services"]["kubeadm_kube-proxy"]["conntrack"].pop("min",None)


def reset_installation_env(group: NodeGroup) -> Optional[RunnersGroupResult]:
    log = group.cluster.log

    log.debug("Cleaning up previous installation...")

    cluster: KubernetesCluster = group.cluster
    procedure: str = cluster.context['initial_procedure']

    drain_timeout = cluster.procedure_inventory.get('drain_timeout')
    grace_period = cluster.procedure_inventory.get('grace_period')

    # if we perform "add" or "remove" node procedure
    # then we need to additionally perform "drain" and "delete" during reset
    nodes_for_draining = cluster.make_group([])

    # perform FULL reset only for "add" or "remove" procedures
    # do not perform full reset on cluster (re)installation, it could hang on last etcd member
    # nodes should be deleted only during "add" or "remove" procedures
    full_reset = procedure != 'install'

    nodes_for_manual_etcd_remove = cluster.make_group([])
    active_nodes = group.get_online_nodes(True)

    if procedure == 'remove_node':
        # We need to manually remove members from etcd for "remove" procedure,
        # only if corresponding nodes are not active.
        # Otherwise, they will be removed by "kubeadm reset" command.
        nodes_for_manual_etcd_remove = group.exclude_group(active_nodes)

        # kubectl drain command hands on till timeout is exceeded for nodes which are off
        # so we should drain only active nodes
        nodes_for_draining = active_nodes
    elif procedure == 'add_node':
        nodes_for_draining = group

    if not nodes_for_manual_etcd_remove.is_empty():
        log.warning(f"Nodes {nodes_for_manual_etcd_remove.get_hosts()} are considered as not active. "
                    "Full cleanup procedure cannot be performed. "
                    "Corresponding members will be removed from etcd manually.")
        etcd.remove_members(nodes_for_manual_etcd_remove)

    if not nodes_for_draining.is_empty():
        drain_nodes(nodes_for_draining, drain_timeout=drain_timeout, grace_period=grace_period)

    if full_reset and not active_nodes.is_empty():
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
            'sudo mkdir -p /etc/kubernetes/manifests; ', warn=True, pty=True)

        # Disabled initial prune for images prepull feature. Need analysis for possible negative impact.
        # result.update(cri.prune(active_nodes, all_implementations=True))

        log.debug(f"Nodes {active_nodes.get_hosts()} cleaned up successfully:\n" + "%s" % result)

    if full_reset:
        return delete_nodes(group)

    return None


def drain_nodes(group: NodeGroup, disable_eviction: bool = False,
                drain_timeout: int = None, grace_period: int = None) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    control_plane = cluster.get_unchanged_nodes().having_roles(['control-plane']).get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list():
        node_name = node.get_node_name()

        # Split stdout into lines
        stdout_lines = stdout.split('\n')[1:]
        # Check if node_name exactly matches any line
        if node_name in stdout_lines:
            log.debug("Draining node %s..." % node_name)
            drain_cmd = prepare_drain_command(
                cluster, node_name,
                disable_eviction=disable_eviction, drain_timeout=drain_timeout, grace_period=grace_period)
            control_plane.sudo(drain_cmd, hide=False, pty=True)
        else:
            log.warning("Node %s is not found in cluster and can't be drained" % node_name)

    return control_plane.sudo("kubectl get nodes")


def delete_nodes(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    control_plane = cluster.get_unchanged_nodes().having_roles(['control-plane']).get_first_member()
    result = control_plane.sudo("kubectl get nodes -o custom-columns=NAME:.metadata.name")

    stdout = list(result.values())[0].stdout
    log.verbose("Detected the following nodes in cluster:\n%s" % stdout)

    for node in group.get_ordered_members_list():
        node_name = node.get_node_name()
        
        # Split stdout into lines
        stdout_lines = stdout.split('\n')[1:]
        # Check if node_name exactly matches any line
        if node_name in stdout_lines:
            log.debug("Deleting node %s from the cluster..." % node_name)
            control_plane.sudo("kubectl delete node %s" % node_name, hide=False, pty=True)
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
    node_name = node.get_node_name()

    join_config = components.get_init_config(cluster, node, init=False, join_dict=join_dict)
    config = components.get_kubeadm_config(cluster, join_config)

    utils.dump_file(cluster, config, 'join-config_%s.yaml' % node_name)

    log.debug("Uploading init config to control-plane '%s'..." % node_name)
    node.sudo("mkdir -p /etc/kubernetes")
    node.put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    components.create_kubeadm_patches_for_node(cluster, node)

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
        hide=False, pty=True)
    copy_admin_config(log, node)

    components.wait_for_pods(node)


@contextmanager
def local_admin_config(nodes: NodeGroup) -> Iterator[str]:
    temp_filepath = utils.get_remote_tmp_path()

    cluster_name = nodes.cluster.inventory['cluster_name']

    try:
        with nodes.new_executor() as exe:
            for defer in exe.group.get_ordered_members_list():
                internal_address = defer.get_config()['internal_address']
                if utils.isipv(internal_address, [6]):
                    internal_address = f"[{internal_address}]"

                defer.sudo(
                    f"cp /root/.kube/config {temp_filepath} "
                    f"&& sudo sed -i 's/{cluster_name}/{internal_address}/' {temp_filepath}")
        yield temp_filepath
    finally:
        nodes.sudo(f'rm -f {temp_filepath}')


def copy_admin_config(logger: log.EnhancedLogger, nodes: NodeGroup) -> None:
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
        if utils.isipv(public_cluster_ip, [6]):
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
    node_name = first_control_plane.get_node_name()

    init_config = components.get_init_config(cluster, first_control_plane, init=True)
    config = components.get_kubeadm_config(cluster, init_config)

    utils.dump_file(cluster, config, 'init-config_%s.yaml' % node_name)

    log.debug("Uploading init config to initial control_plane...")
    first_control_plane.sudo("mkdir -p /etc/kubernetes")
    first_control_plane.put(io.StringIO(config), '/etc/kubernetes/init-config.yaml', sudo=True)

    # put control-plane patches
    components.create_kubeadm_patches_for_node(cluster, first_control_plane)

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
        hide=False, pty=True)

    copy_admin_config(log, first_control_plane)

    kubeconfig_filepath = fetch_admin_config(cluster)
    summary.schedule_report(cluster.context, summary.SummaryItem.KUBECONFIG, kubeconfig_filepath)

    # Remove default resolvConf from kubelet-config ConfigMap for debian OS family
    first_control_plane.call(components.patch_kubelet_configmap)

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

    components.wait_for_pods(first_control_plane)
    # refresh cluster installation status in cluster context
    is_cluster_installed(cluster)


def wait_uncordon(node: NodeGroup) -> None:
    cluster = node.cluster
    timeout_config = cluster.inventory['globals']['expect']['pods']['kubernetes']
    # This forces to use local API server and waits till it is up.
    with local_admin_config(node) as kubeconfig:
        node.wait_command_successful(f"kubectl --kubeconfig {kubeconfig} uncordon {node.get_node_name()} > /dev/null",
                                     hide=False, pty=True,
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
        status_cmd = "kubectl get nodes %s -o jsonpath='{.items[*].status.conditions[?(@.type==\"%s\")].status}{\"\\n\"}'"
    else:
        status_cmd = "kubectl get nodes %s -o jsonpath='{.status.conditions[?(@.type==\"%s\")].status}{\"\\n\"}'"

    timeout = int(cluster.inventory['globals']['nodes']['ready']['timeout'])
    retries = int(cluster.inventory['globals']['nodes']['ready']['retries'])
    log.debug("Waiting for new kubernetes nodes to become ready, %s retries every %s seconds" % (retries, timeout))
    while retries > 0:
        correct_conditions = 0
        for condition, cond_value in wait_conditions.items():
            result = first_control_plane.sudo(status_cmd % (" ".join(node_names), condition), warn=True, pty=True)
            node_result = result.get_simple_result()
            if node_result.failed:
                log.debug(f"kubectl exited with non-zero exit code. Haproxy or kube-apiserver are not yet started?")
                log.verbose(node_result)
                break
            for line in node_result.stdout.rstrip('\n').split('\n'):
                condition_results = line.split(" ")
                correct_values = [value for value in condition_results if value == cond_value]
                if len(correct_values) == len(node_names):
                    correct_conditions = correct_conditions + 1
                    log.debug(f"Condition {condition} is {cond_value} for all nodes.")
                    break
            else:
                log.debug(f"Condition {condition} is not met, retrying")
                break

        if correct_conditions == len(wait_conditions):
            log.debug("All nodes are ready!")
            return
        else:
            retries = retries - 1
            time.sleep(timeout)

    raise Exception(f"Nodes did not become ready in the expected time, {retries} retries every {timeout} seconds. "
                    "Try to increase node.ready.retries parameter in globals: "
                    "https://github.com/Netcracker/KubeMarine/blob/main/documentation/Installation.md#globals")


def init_workers(group: NodeGroup) -> None:
    if group.is_empty():
        return

    cluster: KubernetesCluster = group.cluster
    join_dict = cluster.context.get("join_dict", get_join_dict(group))

    join_config = components.get_init_config(cluster, group, init=False, join_dict=join_dict)
    config = yaml.dump(join_config)

    utils.dump_file(cluster, config, 'join-config-workers.yaml')

    group.sudo("mkdir -p /etc/kubernetes")
    group.put(io.StringIO(config), '/etc/kubernetes/join-config.yaml', sudo=True)

    # put control-plane patches
    for node in group.get_ordered_members_list():
        components.create_kubeadm_patches_for_node(cluster, node)

    cluster.log.debug('Joining workers...')

    for node in group.get_ordered_members_list():
        node.sudo(
            "kubeadm join --config=/etc/kubernetes/join-config.yaml"
            " --ignore-preflight-errors='" + cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors'] + "'"
            " --v=5",
            hide=False, pty=True)

        components.wait_for_pods(node)


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
        "'{range .items[*]}{\"node: \"}{.metadata.name}{\"\\ntaints: \"}{.spec.taints}{\"\\n\"}{end}'")


def is_cluster_installed(cluster: KubernetesCluster) -> bool:
    cluster.log.verbose('Searching for already installed cluster...')
    try:
        results = cluster.nodes['control-plane'].sudo(
            'kubectl cluster-info', pty=True, warn=True, timeout=15)
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


def upgrade_first_control_plane(upgrade_group: NodeGroup, cluster: KubernetesCluster, **drain_kwargs: Any) -> None:
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    node_name = first_control_plane.get_node_name()

    if not upgrade_group.has_node(node_name):
        cluster.log.debug("First control-plane \"%s\" upgrade is not required" % node_name)
        return

    cluster.log.debug("Upgrading first control-plane \"%s\"" % node_name)

    # put control-plane patches
    components.create_kubeadm_patches_for_node(cluster, first_control_plane)

    flags = ("-f --certificate-renewal=true "
             f"--ignore-preflight-errors='{cluster.inventory['services']['kubeadm_flags']['ignorePreflightErrors']}' "
             f"--patches=/etc/kubernetes/patches")

    drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
    first_control_plane.sudo(drain_cmd, hide=False, pty=True)

    upgrade_cri_if_required(first_control_plane)
    fix_flag_kubelet(first_control_plane)

    first_control_plane.sudo(
        f"sudo kubeadm upgrade apply {version} {flags} && "
        f"sudo kubectl uncordon {node_name} && "
        f"sudo systemctl restart kubelet", hide=False, pty=True)

    copy_admin_config(cluster.log, first_control_plane)

    expect_kubernetes_version(cluster, version, apply_filter=node_name)
    components.wait_for_pods(first_control_plane)
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
            components.create_kubeadm_patches_for_node(cluster, node)

            drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
            node.sudo(drain_cmd, hide=False, pty=True)

            upgrade_cri_if_required(node)
            fix_flag_kubelet(node)

            node.sudo(
                f"sudo kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
                f"sudo kubectl uncordon {node_name} && "
                f"sudo systemctl restart kubelet",
                hide=False, pty=True)

            expect_kubernetes_version(cluster, version, apply_filter=node_name)
            copy_admin_config(cluster.log, node)
            components.wait_for_pods(node)
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
        components.create_kubeadm_patches_for_node(cluster, node)

        drain_cmd = prepare_drain_command(cluster, node_name, **drain_kwargs)
        first_control_plane.sudo(drain_cmd, hide=False, pty=True)

        upgrade_cri_if_required(node)
        fix_flag_kubelet(node)

        node.sudo(
            "kubeadm upgrade node --certificate-renewal=true --patches=/etc/kubernetes/patches && "
            "sudo systemctl restart kubelet", pty=True)

        first_control_plane.sudo("kubectl uncordon %s" % node_name, hide=False)

        expect_kubernetes_version(cluster, version, apply_filter=node_name)
        # workers do not have system pods to wait for their start
        exclude_node_from_upgrade_list(first_control_plane, node_name)

        components.wait_for_pods(node)


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

    if 'containerd' in cluster.context["upgrade"]["required"]['packages']:
        cri_packages = cluster.get_package_association_for_node(group.get_host(), 'containerd', 'package_name')

        log.debug(f"Installing {cri_packages} on node: {group.get_node_name()}")
        packages.install(group, include=cri_packages, pty=True)
        log.debug(f"Restarting all containers on node: {group.get_node_name()}")
        group.sudo("crictl rm -fa", warn=True)
    else:
        log.debug("'containerd' package upgrade is not required")

    # upgrade of sandbox_image is currently not supported for migrate_kubemarine
    if cluster.context["upgrade"]["required"].get('containerdConfig', False):
        containerd.configure_containerd(group)
    else:
        log.debug("'containerd' configuration upgrade is not required")


def verify_upgrade_versions(cluster: KubernetesCluster) -> None:
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    upgrade_version = get_kubernetes_version(cluster.inventory)

    k8s_nodes_group = cluster.make_group_from_roles(['control-plane', 'worker'])
    for node in k8s_nodes_group.get_ordered_members_list():
        cluster.log.debug(f"Verifying current k8s version for node {node.get_node_name()}")
        result = first_control_plane.sudo("kubectl get nodes "
                                          f"{node.get_node_name()}"
                                          " -o custom-columns='VERSION:.status.nodeInfo.kubeletVersion' "
                                          "| grep -vw ^VERSION ")
        curr_version = list(result.values())[0].stdout
        test_version_upgrade_possible(curr_version, upgrade_version, skip_equal=True)


def get_procedure_upgrade_version(cluster: KubernetesCluster) -> str:
    upgrade_version: str = cluster.procedure_inventory['upgrade_plan'][cluster.context["upgrade_step"]]
    return upgrade_version


def get_kubernetes_version(inventory: dict) -> str:
    kubernetes_version: str
    if inventory.get("services", {}).get("kubeadm", {}).get("kubernetesVersion") is not None:
        kubernetes_version = str(inventory['services']['kubeadm']['kubernetesVersion'])
    else:
        kubernetes_version = static.DEFAULTS['services']['kubeadm']['kubernetesVersion']

    return kubernetes_version


@enrichment(EnrichmentStage.FULL)
def verify_version(cluster: KubernetesCluster) -> None:
    version = get_kubernetes_version(cluster.inventory)
    verify_allowed_version(version)
    verify_supported_version(version, cluster.log)


def verify_allowed_version(version: str) -> str:
    allowed_versions = static.KUBERNETES_VERSIONS['compatibility_map'].keys()
    if version not in allowed_versions:
        raise errors.KME('KME0008',
                         version=version,
                         allowed_versions=', '.join(map(repr, allowed_versions)))

    return version


def verify_supported_version(target_version: str, logger: log.EnhancedLogger) -> None:
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
        result = node.sudo(command, warn=True, pty=True)
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


def is_version_upgrade_possible(old: str, new: str) -> bool:
    try:
        test_version_upgrade_possible(old, new)
        return True
    except Exception:
        return False


def test_version_upgrade_possible(old: str, new: str, skip_equal: bool = False) -> None:
    old = old.strip()
    new = new.strip()
    old_version_key = utils.version_key(old)
    new_version_key = utils.version_key(new)

    # test new is greater than old
    if old_version_key > new_version_key:
        raise Exception(ERROR_DOWNGRADE % (old, new))

    # test new is the same as old
    if old_version_key == new_version_key and not skip_equal:
        raise Exception(ERROR_SAME % (old, new))

    # test major step is not greater than 1
    if new_version_key[0] - old_version_key[0] > 1:
        raise Exception(ERROR_MAJOR_RANGE_EXCEEDED % (old, new))

    # test minor step is not greater than 1
    if new_version_key[1] - old_version_key[1] > 1:
        raise Exception(ERROR_MINOR_RANGE_EXCEEDED % (old, new))

    # test the target version is the latest supported patch version
    new_minor_version = utils.minor_version(new)
    latest_supported_patch_version = max(
        (v for v in static.KUBERNETES_VERSIONS['compatibility_map']
         if utils.minor_version(v) == new_minor_version),
        key=utils.version_key)

    if new != latest_supported_patch_version:
        raise Exception(ERROR_NOT_LATEST_PATCH % (new, latest_supported_patch_version))


def recalculate_proper_timeout(cluster: KubernetesCluster, timeout: int) -> int:
    try:
        amount_str = cluster.nodes['control-plane'].get_first_member().sudo('kubectl get pods -A | wc -l').get_simple_out()
        return timeout * int(amount_str)
    except Exception:
        return timeout * 10 * cluster.nodes['all'].nodes_amount()


def exclude_node_from_upgrade_list(first_control_plane: NodeGroup, node_name: str) -> None:
    first_control_plane.sudo('sed -i \'/%s/d\' /etc/kubernetes/nodes-k8s-versions.txt' % node_name, warn=True)


def autodetect_non_upgraded_nodes(cluster: KubernetesCluster, future_version: str) -> List[str]:
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    try:
        nodes_list_result = (first_control_plane.sudo('[ ! -f /etc/kubernetes/nodes-k8s-versions.txt ] || '
                                                     'sudo cat /etc/kubernetes/nodes-k8s-versions.txt')
                                .get_simple_out())
        if not nodes_list_result:
            cluster.log.debug('Cluster status file /etc/kubernetes/nodes-k8s-versions.txt unexist or empty, '
                              'the new file will be created.')
            nodes_list_result = first_control_plane.sudo('sudo kubectl get nodes --no-headers -o custom-columns=\''
                                              'VERSION:.status.nodeInfo.kubeletVersion,'
                                              'NAME:.metadata.name,'
                                              'STATUS:.status.conditions[-1].type\'').get_simple_result().stdout
            nodes_list_result = (f'# This file contains a cached list of nodes and versions '
                                   'required to continue the Kubernetes upgrade procedure if it fails. '
                                   'If all the nodes are completely updated or you manually fixed the '
                                   f'problem that occurred during the upgrade, you can delete it.\n{nodes_list_result}')
            first_control_plane.put(io.StringIO(nodes_list_result), '/etc/kubernetes/nodes-k8s-versions.txt',
                                    backup=False, sudo=True)
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
        version, node_name, status = list(filter(len, line.split(' ')))
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

    :param group: single-node NodeGroup where prepull should be performed.
    :param collector: CollectorCallback instance
    :return: NodeGroupResult from all nodes in presented group.
    """

    cluster: KubernetesCluster = group.cluster
    kubeadm_init = components.get_init_config(cluster, group, init=True)
    config = components.get_kubeadm_config(cluster, kubeadm_init)

    group.put(io.StringIO(config), '/etc/kubernetes/prepull-config.yaml', sudo=True)

    return group.sudo("kubeadm config images pull --config=/etc/kubernetes/prepull-config.yaml",
                      pty=True, callback=collector)


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

        property_ = summary.SummaryItem.CONTROL_PLANES if role == 'control-plane' else summary.SummaryItem.WORKERS
        value = f'{ready}/{members}'
        summary.schedule_report(cluster.context, property_, value)


def get_nodes_description_cmd() -> str:
    return 'kubectl get node -o yaml'


def get_nodes_description(cluster: KubernetesCluster) -> dict:
    cmd = get_nodes_description_cmd()
    result = cluster.nodes['control-plane'].get_any_member().sudo(cmd)
    cluster.log.verbose(result)
    data: dict = yaml.safe_load(list(result.values())[0].stdout)
    return data


def get_actual_roles(nodes_description: dict) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for node_description in nodes_description['items']:
        node_name = node_description['metadata']['name']
        labels = node_description['metadata']['labels']
        result[node_name] = []
        if 'node-role.kubernetes.io/control-plane' in labels:
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


def fix_flag_kubelet(group: NodeGroup) -> bool:
    kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
    cluster = group.cluster
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
            if components.is_container_runtime_not_configurable(cluster):
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
