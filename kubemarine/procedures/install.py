#!/usr/bin/env python3
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


from collections import OrderedDict
from typing import Callable

import fabric
import yaml
import os
import io

from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.errors import KME
from kubemarine import system, sysctl, haproxy, keepalived, kubernetes, plugins, \
    kubernetes_accounts, selinux, thirdparties, admission, audit, coredns, cri, packages, apparmor
from kubemarine.core import flow, utils, summary
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine import kubernetes

def _applicable_for_new_nodes_with_roles(*roles):
    """
    Decorator to annotate installation methods.
    If there are no new nodes with the specified roles to be added / installed to the cluster,
    the decorator skips execution of the method.
    Otherwise, it runs the annotated method with the calculated group of nodes with the specified roles.
    Note that the signature of annotated method should be f(NodeGroup),
    but the resulting wrapping method will be f(KubernetesCluster).

    :param roles: roles of nodes for which the annotated method is applicable.
    :return: new wrapping method.
    """
    if not roles:
        raise Exception(f'Roles are not defined')

    def roles_wrapper(fn: Callable[[NodeGroup], None]):
        def cluster_wrapper(cluster: KubernetesCluster):
            candidate_group = cluster.nodes['all'].get_new_nodes_or_self()
            group = cluster.make_group([])
            for role in roles:
                group = group.include_group(cluster.nodes.get(role))
            group = group.intersection_group(candidate_group)
            if not group.is_empty():
                fn(group)
            else:
                fn_name = fn.__module__ + '.' + fn.__qualname__
                cluster.log.debug(f"Skip running {fn_name} as no new node with roles {roles} has been found.")

        return cluster_wrapper

    return roles_wrapper


def system_prepare_check_sudoer(cluster):
    not_sudoers = []
    for host, node_context in cluster.context['nodes'].items():
        access_info = node_context['access']
        if access_info['online'] and access_info['sudo'] == 'Root':
            cluster.log.debug("%s online and has root" % host)
        else:
            not_sudoers.append(host)

    if not_sudoers:
        raise KME("KME0005", hostnames=not_sudoers)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_check_system(group: NodeGroup):
    cluster = group.cluster
    cluster.log.debug(system.fetch_os_versions(cluster))
    for address, context in cluster.context["nodes"].items():
        if address not in group.nodes:
            continue
        if context["os"]["family"] == "unsupported":
            raise Exception('%s host operating system is unsupported' % address)
        if context["os"]["family"] == "unknown":
            supported_os_versions = []
            os_family_list = cluster.globals["compatibility_map"]["distributives"][context["os"]["name"]]
            for os_family_item in os_family_list:
                supported_os_versions.extend(os_family_item["versions"])
            raise Exception("%s running on unknown %s version. "
                            "Expected %s, got '%s'" % (address,
                                                       context["os"]["name"],
                                                       supported_os_versions,
                                                       context["os"]["version"]))


def system_prepare_check_cluster_installation(cluster):
    if kubernetes.is_cluster_installed(cluster):
        cluster.log.debug('Cluster already installed and available at %s' % cluster.context['controlplain_uri'])
    else:
        cluster.log.debug('There is no any installed cluster')


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_chrony(group: NodeGroup):
    cluster = group.cluster
    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') is None:
        cluster.log.debug("Skipped - NTP servers from chrony is not defined in config file")
        return
    group.call(system.configure_chronyd)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_timesyncd(group: NodeGroup):
    cluster = group.cluster
    if not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') and \
            not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP'):
        cluster.log.debug("Skipped - NTP servers from timesyncd is not defined in config file")
        return
    group.call(system.configure_timesyncd)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_sysctl(group: NodeGroup):
    cluster = group.cluster
    if cluster.inventory['services'].get('sysctl') is None or not cluster.inventory['services']['sysctl']:
        cluster.log.debug("Skipped - sysctl is not defined or empty in config file")
        return
    group.call_batch([
        sysctl.configure,
        sysctl.reload,
    ])


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_setup_selinux(group: NodeGroup):
    group.call(selinux.setup_selinux)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_setup_apparmor(group: NodeGroup):
    group.call(apparmor.setup_apparmor)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_disable_firewalld(group: NodeGroup):
    group.call(system.disable_firewalld)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_disable_swap(group: NodeGroup):
    group.call(system.disable_swap)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_modprobe(group: NodeGroup):
    group.call(system.setup_modprobe)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_install_audit(group: NodeGroup):
    group.call(audit.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_prepare_audit_daemon(group: NodeGroup):
    group.call(audit.apply_audit_rules)


@_applicable_for_new_nodes_with_roles('control-plane')
def system_prepare_policy(group: NodeGroup):
    """
    Task generates rules for logging kubernetes and on audit
    """
    cluster = group.cluster
    api_server_extra_args = cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']
    audit_log_dir = os.path.dirname(api_server_extra_args['audit-log-path'])
    audit_file_name = api_server_extra_args['audit-policy-file']
    audit_policy_dir = os.path.dirname(audit_file_name)
    group.sudo(f"mkdir -p {audit_log_dir} && sudo mkdir -p {audit_policy_dir}")
    policy_config = cluster.inventory['services']['audit'].get('cluster_policy')
    collect_node = group.get_ordered_members_list(provide_node_configs=True)

    if policy_config:
        policy_config_file = yaml.dump(policy_config)
        utils.dump_file(cluster, policy_config_file, 'audit-policy.yaml')
        #download rules in cluster
        for node in collect_node:
            node['connection'].put(io.StringIO(policy_config_file), audit_file_name, sudo=True, backup=True)
        audit_config = True
        cluster.log.debug("Audit cluster policy config")
    else:
        audit_config = False
        cluster.log.debug("Audit cluster policy config is empty, nothing will be configured ")

    if kubernetes.is_cluster_installed(cluster) and audit_config is True and cluster.context['initial_procedure'] != 'add_node':
        for control_plane in collect_node:
            config_new = (kubernetes.get_kubeadm_config(cluster.inventory))

            # TODO: when k8s v1.21 is excluded from Kubemarine, this condition should be removed
            # and only "else" branch remains
            if "v1.21" in cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]:
                control_plane['connection'].put(io.StringIO(config_new), '/etc/kubernetes/audit-on-config.yaml', sudo=True)

                control_plane['connection'].sudo(f"kubeadm init phase control-plane apiserver "
                                             f"--config=/etc/kubernetes/audit-on-config.yaml && "
                                             f"sudo sed -i 's/--bind-address=.*$/--bind-address="
                                             f"{control_plane['internal_address']}/' "
                                             f"/etc/kubernetes/manifests/kube-apiserver.yaml")
            else:
                # we need InitConfiguration in audit-on-config.yaml file to take into account kubeadm patch for apiserver
                init_config = {
                    'apiVersion': group.cluster.inventory["services"]["kubeadm"]['apiVersion'],
                    'kind': 'InitConfiguration',
                    'localAPIEndpoint': {
                        'advertiseAddress': control_plane['internal_address']
                    },
                    'patches': {
                        'directory': '/etc/kubernetes/patches'
                    }
                }

                config_new = config_new + "---\n" + yaml.dump(init_config, default_flow_style=False)

                control_plane['connection'].put(io.StringIO(config_new), '/etc/kubernetes/audit-on-config.yaml', sudo=True)

                kubernetes.create_kubeadm_patches_for_node(cluster, control_plane)

                control_plane['connection'].sudo(f"kubeadm init phase control-plane apiserver "
                                             f"--config=/etc/kubernetes/audit-on-config.yaml ")

            if cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
                control_plane['connection'].call(utils.wait_command_successful,
                                                 command="crictl rm -f $(sudo crictl ps --name kube-apiserver -q)")
            else:
                control_plane['connection'].call(utils.wait_command_successful,
                                                 command="docker stop $(sudo docker ps -q -f 'name=k8s_kube-apiserver'"
                                                         " | awk '{print $1}')")
            control_plane['connection'].call(utils.wait_command_successful, command="kubectl get pod -n kube-system")
            control_plane['connection'].sudo("kubeadm init phase upload-config kubeadm "
                                             "--config=/etc/kubernetes/audit-on-config.yaml")


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_dns_hostname(group: NodeGroup):
    cluster = group.cluster
    with RemoteExecutor(cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            cluster.log.debug("Changing hostname '%s' = '%s'" % (node["connect_to"], node["name"]))
            node["connection"].sudo("hostnamectl set-hostname %s" % node["name"])


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_dns_resolv_conf(group: NodeGroup):
    cluster = group.cluster
    if cluster.inventory["services"].get("resolv.conf") is None:
        cluster.log.debug("Skipped - resolv.conf section not defined in config file")
        return

    system.update_resolv_conf(group, config=cluster.inventory["services"].get("resolv.conf"))
    cluster.log.debug(group.sudo("ls -la /etc/resolv.conf; sudo lsattr /etc/resolv.conf"))


def system_prepare_dns_etc_hosts(cluster):
    config = system.generate_etc_hosts_config(cluster.inventory, cluster)

    utils.dump_file(cluster, config, 'etc_hosts')
    cluster.log.debug("\nUploading...")

    group = cluster.nodes['all'].get_final_nodes()

    system.update_etc_hosts(group, config=config)
    cluster.log.debug(group.sudo("ls -la /etc/hosts"))


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_package_manager_configure(group: NodeGroup):
    cluster = group.cluster
    repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
    if not repositories:
        cluster.log.debug("Skipped - no repositories defined for configuration")
        return

    group.call_batch([
        packages.backup_repo,
        packages.add_repo
    ], **{
        "kubemarine.packages.add_repo": {
            "repo_data": repositories,
            "repo_filename": "predefined"
        }
    })

    cluster.log.debug("Nodes contain the following repositories:")
    cluster.log.debug(packages.ls_repofiles(group))


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_package_manager_manage_packages(group: NodeGroup):
    group.call_batch([
        manage_mandatory_packages,
        manage_custom_packages
    ])


def manage_mandatory_packages(group: NodeGroup):
    cluster = group.cluster

    with RemoteExecutor(cluster) as exe:
        for node in group.get_ordered_members_list():
            pkgs = []
            for package in cluster.inventory["services"]["packages"]['mandatory'].keys():
                hosts_to_packages = packages.get_association_hosts_to_packages(node, cluster.inventory, package)
                pkgs.extend(next(iter(hosts_to_packages.values()), []))

            if pkgs:
                cluster.log.debug(f"Installing {pkgs} on {node.get_node_name()!r}")
                packages.install(node, pkgs)

    return exe.get_merged_result()


def manage_custom_packages(group: NodeGroup):
    cluster = group.cluster
    batch_tasks = []
    batch_parameters = {}

    packages_section = cluster.inventory["services"].get("packages", {})
    if packages_section.get("remove", {}).get("include"):
        batch_tasks.append(packages.remove)
        batch_parameters["kubemarine.packages.remove"] = {
            "include": packages_section['remove']['include'],
            "exclude": packages_section['remove'].get('exclude')
        }

    if packages_section.get("install", {}).get("include"):
        batch_tasks.append(packages.install)
        batch_parameters["kubemarine.packages.install"] = {
            "include": packages_section['install']['include'],
            "exclude": packages_section['install'].get('exclude')
        }

    if packages_section.get("upgrade", {}).get("include"):
        batch_tasks.append(packages.upgrade)
        batch_parameters["kubemarine.packages.upgrade"] = {
            "include": packages_section['upgrade']['include'],
            "exclude": packages_section['upgrade'].get('exclude')
        }

    if not batch_tasks:
        cluster.log.debug("Skipped - no packages configuration defined in config file")
        return

    try:
        batch_results = group.call_batch(batch_tasks, **batch_parameters)
    except fabric.group.GroupException:
        cluster.log.verbose('Exception occurred! Trying to handle is there anything updated or not...')
        # todo develop cases when we can continue even if exception occurs
        raise

    any_changes_found = False
    for action, results in batch_results.items():
        cluster.log.verbose('Verifying packages changes after \'%s\' action...' % action)
        for conn, result in results.items():
            node = cluster.make_group([conn])
            if not packages.no_changes_found(node, action, result):
                cluster.log.verbose('Packages changed at %s' % conn.host)
                any_changes_found = True

    if any_changes_found:
        cluster.log.verbose('Packages changed, scheduling nodes restart...')
        cluster.schedule_cumulative_point(system.reboot_nodes)
    else:
        cluster.log.verbose('No packages changed, nodes restart will not be scheduled')


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_cri_install(group: NodeGroup):
    """
    Task which is used to install CRI. Could be skipped, if CRI already installed.
    """
    group.call(cri.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_cri_configure(group: NodeGroup):
    """
    Task which is used to configure CRI. Could be skipped, if CRI already configured.
    """
    group.call(cri.configure)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_thirdparties(group: NodeGroup):
    cluster = group.cluster
    if not cluster.inventory['services'].get('thirdparties', {}):
        cluster.log.debug("Skipped - no thirdparties defined in config file")
        return

    group.call(thirdparties.install_all_thirparties)


@_applicable_for_new_nodes_with_roles('balancer')
def deploy_loadbalancer_haproxy_install(group: NodeGroup):
    group.call(haproxy.install)


def deploy_loadbalancer_haproxy_configure(cluster):

    if not cluster.inventory['services'].get('loadbalancer', {}) \
            .get('haproxy', {}).get('keep_configs_updated', True):
        cluster.log.debug('Skipped - haproxy balancers configs update manually disabled')
        return

    group = None

    if "balancer" in cluster.nodes:

        if cluster.context['initial_procedure'] != 'remove_node':
            group = cluster.nodes['balancer'].get_new_nodes_or_self()

        if not cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker')).get_changed_nodes().is_empty():
            group = cluster.nodes['balancer'].get_final_nodes()

    if group is None or group.is_empty():
        cluster.log.debug('Skipped - no balancers to perform')
        return

    with RemoteExecutor(cluster):
        group.call_batch([
            haproxy.configure,
            haproxy.override_haproxy18,
            haproxy.restart
        ])


def deploy_loadbalancer_keepalived_install(cluster):
    group = None
    if 'vrrp_ips' in cluster.inventory and cluster.inventory['vrrp_ips']:

        group = cluster.nodes['keepalived']

        # if remove/add node, then reconfigure only new keepalives
        if cluster.context['initial_procedure'] != 'install':
            group = cluster.nodes['keepalived'].get_new_nodes()

        # if balancer added or removed - reconfigure all keepalives
        # todo The method is currently not invoked for remove node.
        #  So why we try to install all keepalives for add_node but not touch them for remove_node?
        if not cluster.nodes['balancer'].get_changed_nodes().is_empty():
            group = cluster.nodes['keepalived'].get_final_nodes()

    if group is None or group.is_empty():
        cluster.log.debug('Skipped - no VRRP IPs to perform')
        return

    # add_node will impact all keepalived
    group.call(keepalived.install)


def deploy_loadbalancer_keepalived_configure(cluster):
    group = None
    if 'vrrp_ips' in cluster.inventory and cluster.inventory['vrrp_ips']:

        group = cluster.nodes['keepalived'].get_final_nodes()

        # if remove/add node, then reconfigure only new keepalives
        if cluster.context['initial_procedure'] != 'install':
            group = cluster.nodes['keepalived'].get_new_nodes()

        # if balancer added or removed - reconfigure all keepalives
        if not cluster.nodes['balancer'].get_changed_nodes().is_empty():
            group = cluster.nodes['keepalived'].get_final_nodes()

    if group is None or group.is_empty():
        cluster.log.debug('Skipped - no VRRP IPs to perform')
        return

    # add_node will impact all keepalived
    group.call(keepalived.configure)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_reset(group: NodeGroup):
    group.call(kubernetes.reset_installation_env)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_install(group: NodeGroup):
    group.cluster.log.debug("Setting up Kubernetes...")
    group.call(kubernetes.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_prepull_images(group: NodeGroup):
    group.cluster.log.debug("Prepulling Kubernetes images...")
    group.call(kubernetes.images_grouped_prepull)


def deploy_kubernetes_init(cluster: KubernetesCluster):
    cluster.nodes['control-plane'].call_batch([
        kubernetes.init_first_control_plane,
        kubernetes.join_other_control_planes
    ])

    if 'worker' in cluster.nodes:
        cluster.nodes.get('worker').new_group(
            apply_filter=lambda node: 'control-plane' not in node['roles']) \
            .call(kubernetes.init_workers)

    cluster.nodes['all'].call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])

    kubernetes.schedule_running_nodes_report(cluster)


def deploy_coredns(cluster):
    config = coredns.generate_configmap(cluster.inventory)

    cluster.log.debug('Applying patch...')
    cluster.log.debug(coredns.apply_patch(cluster))

    cluster.log.debug('Applying configmap...')
    cluster.log.debug(coredns.apply_configmap(cluster, config))


def deploy_plugins(cluster):
    plugins.install(cluster)


def deploy_accounts(cluster):
    kubernetes_accounts.install(cluster)


def overview(cluster):
    cluster.log.debug("Retrieving cluster status...")
    control_plane = cluster.nodes["control-plane"].get_final_nodes().get_first_member()
    cluster.log.debug("\nNAMESPACES:")
    control_plane.sudo("kubectl get namespaces", hide=False)
    cluster.log.debug("\nNODES:")
    control_plane.sudo("kubectl get nodes -o wide", hide=False)
    cluster.log.debug("\nPODS:")
    control_plane.sudo("kubectl get pods -A -o=wide", hide=False)
    cluster.log.debug("\nREPLICA SETS:")
    control_plane.sudo("kubectl get rs -A", hide=False)
    cluster.log.debug("\nDAEMON SETS:")
    control_plane.sudo("kubectl get ds -A", hide=False)
    cluster.log.debug("\nSERVICES:")
    control_plane.sudo("kubectl get svc -A -o wide", hide=False)
    cluster.log.debug("\nINGRESS:")
    control_plane.sudo("kubectl get ing -A -o wide", hide=False)
    cluster.log.debug("\nDESCRIPTION:")
    control_plane.sudo("kubectl describe nodes", hide=False)
    cluster.log.debug("\n")
    control_plane.sudo("kubectl cluster-info", hide=False, warn=True)


tasks = OrderedDict({
    "prepare": {
        "check": {
            "sudoer": system_prepare_check_sudoer,
            "system": system_prepare_check_system,
            "cluster_installation": system_prepare_check_cluster_installation
        },
        "dns": {
            "hostname": system_prepare_dns_hostname,
            "etc_hosts": system_prepare_dns_etc_hosts,
            "resolv_conf": system_prepare_dns_resolv_conf
        },
        "package_manager": {
            "configure": system_prepare_package_manager_configure,
            "manage_packages": system_prepare_package_manager_manage_packages
        },
        "ntp": {
            "chrony": system_prepare_system_chrony,
            "timesyncd": system_prepare_system_timesyncd
        },
        "system": {
            "setup_selinux": system_prepare_system_setup_selinux,
            "setup_apparmor": system_prepare_system_setup_apparmor,
            "disable_firewalld": system_prepare_system_disable_firewalld,
            "disable_swap": system_prepare_system_disable_swap,
            "modprobe": system_prepare_system_modprobe,
            "sysctl": system_prepare_system_sysctl,
            "audit": {
                "install": system_install_audit,
                "configure_daemon": system_prepare_audit_daemon,
                "configure_policy": system_prepare_policy
            }
        },
        "cri": {
            "install": system_cri_install,
            "configure": system_cri_configure
        },
        "thirdparties": system_prepare_thirdparties
    },
    "deploy": {
        "loadbalancer": {
            "haproxy": {
                "install": deploy_loadbalancer_haproxy_install,
                "configure": deploy_loadbalancer_haproxy_configure,
            },
            "keepalived": {
                "install": deploy_loadbalancer_keepalived_install,
                "configure": deploy_loadbalancer_keepalived_configure,
            }
        },
        "kubernetes": {
            "reset": deploy_kubernetes_reset,
            "install": deploy_kubernetes_install,
            "prepull_images": deploy_kubernetes_prepull_images,
            "init": deploy_kubernetes_init
        },
        "admission": admission.install,
        "coredns": deploy_coredns,
        "plugins": deploy_plugins,
        "accounts": deploy_accounts
    },
    "overview": overview
})

cumulative_points = {

    # prepare.system.sysctl requires
    # - /proc/sys/net/bridge/bridge-nf-call-iptables
    # - /proc/sys/net/bridge/bridge-nf-call-ip6tables
    # for the following records:
    # - net.ipv4.ip_forward = 1
    # - net.ipv4.ip_nonlocal_bind = 1
    # - net.ipv6.ip_nonlocal_bind = 1
    # - net.ipv6.conf.all.forwarding = 1
    # That is why reboot required BEFORE this task
    system.reboot_nodes: [
        "prepare.system.sysctl"
    ],
    system.verify_system: [
        "prepare.system.sysctl"
    ],
    summary.exec_delayed: [
        flow.END_OF_TASKS
    ]
}


class InstallAction(Action):
    def __init__(self):
        super().__init__('install')
        self.verification_version_result = ""

    def run(self, res: DynamicResources):
        cluster_yml = res.raw_inventory()
        if (cluster_yml.get("services", {})
                and cluster_yml["services"].get("kubeadm", {})
                and cluster_yml["services"]["kubeadm"].get("kubernetesVersion")):
            target_version = cluster_yml["services"]["kubeadm"].get("kubernetesVersion")
            self.verification_version_result = kubernetes.verify_target_version(target_version)

        flow.run_tasks(res, tasks, cumulative_points=cumulative_points)


def main(cli_arguments=None):
    cli_help = '''
    Script for installing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_tasks_flow_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='install')

    install = InstallAction()
    flow.run_actions(context, [install])

    if install.verification_version_result:
        print(install.verification_version_result)


if __name__ == '__main__':
    main()
