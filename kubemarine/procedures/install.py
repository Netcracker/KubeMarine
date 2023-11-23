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
from types import FunctionType
from typing import Callable, List, Dict, cast

import yaml
import io

from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.errors import KME
from kubemarine import (
    system, sysctl, haproxy, keepalived, kubernetes, plugins,
    kubernetes_accounts, selinux, thirdparties, admission, audit, coredns, cri, packages, apparmor, modprobe
)
from kubemarine.core import flow, utils, summary
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback
from kubemarine.core.resources import DynamicResources


TASK_CALLABLE = Callable[[KubernetesCluster], None]
DECORATED_GROUP_CALLABLE = Callable[[NodeGroup], None]


def _applicable_for_new_nodes_with_roles(*roles: str) -> Callable[[DECORATED_GROUP_CALLABLE], TASK_CALLABLE]:
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

    def roles_wrapper(fn: DECORATED_GROUP_CALLABLE) -> TASK_CALLABLE:
        def cluster_wrapper(cluster: KubernetesCluster) -> None:
            candidate_group = cluster.nodes['all'].get_new_nodes_or_self()
            group = cluster.make_group_from_roles(roles)
            group = group.intersection_group(candidate_group)
            if not group.is_empty():
                fn(group)
            else:
                func = cast(FunctionType, fn)
                fn_name = func.__module__ + '.' + func.__qualname__
                cluster.log.debug(f"Skip running {fn_name} as no new node with roles {roles} has been found.")

        return cluster_wrapper

    return roles_wrapper


def system_prepare_check_sudoer(cluster: KubernetesCluster) -> None:
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
def system_prepare_check_system(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
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


def system_prepare_check_cluster_installation(cluster: KubernetesCluster) -> None:
    if kubernetes.is_cluster_installed(cluster):
        cluster.log.debug('Cluster already installed and available at %s' % cluster.context['controlplain_uri'])
    else:
        cluster.log.debug('There is no any installed cluster')


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_chrony(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') is None:
        cluster.log.debug("Skipped - NTP servers from chrony is not defined in config file")
        return
    group.call(system.configure_chronyd)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_timesyncd(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    if not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') and \
            not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP'):
        cluster.log.debug("Skipped - NTP servers from timesyncd is not defined in config file")
        return
    group.call(system.configure_timesyncd)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_sysctl(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster

    if sysctl.is_valid(group):
        cluster.log.debug("Skipped - all necessary kernel parameters are presented")
        return

    group.call_batch([
        sysctl.configure,
        sysctl.reload,
    ])

    cluster.schedule_cumulative_point(system.reboot_nodes)
    cluster.schedule_cumulative_point(system.verify_system)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_setup_selinux(group: NodeGroup) -> None:
    group.call(selinux.setup_selinux)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_setup_apparmor(group: NodeGroup) -> None:
    group.call(apparmor.setup_apparmor)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_disable_firewalld(group: NodeGroup) -> None:
    group.call(system.disable_firewalld)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_disable_swap(group: NodeGroup) -> None:
    group.call(system.disable_swap)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_system_modprobe(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster

    is_updated = modprobe.setup_modprobe(group)
    if is_updated:
        cluster.schedule_cumulative_point(system.reboot_nodes)
        cluster.schedule_cumulative_point(system.verify_system)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_install_audit(group: NodeGroup) -> None:
    group.call(audit.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_prepare_audit(group: NodeGroup) -> None:
    group.call(audit.apply_audit_rules)


@_applicable_for_new_nodes_with_roles('control-plane')
def deploy_kubernetes_audit(group: NodeGroup) -> None:
    """
    Task generates rules for logging kubernetes and on audit
    """
    cluster = group.cluster
    # kubernetes api-server is already installed with target audit configuration for install/add_node procedures.
    if cluster.is_task_completed('deploy.kubernetes.init'):
        cluster.log.debug("Kubernetes audit policy is already configured")
        return

    kubernetes.prepare_audit_policy(group)

    for control_plane in group.get_ordered_members_list():
        node_config = control_plane.get_config()
        config_new = kubernetes.get_kubeadm_config(cluster.inventory)

        # we need InitConfiguration in audit-on-config.yaml file to take into account kubeadm patch for apiserver
        init_config = {
            'apiVersion': cluster.inventory["services"]["kubeadm"]['apiVersion'],
            'kind': 'InitConfiguration',
            'localAPIEndpoint': {
                'advertiseAddress': node_config['internal_address']
            },
            'patches': {
                'directory': '/etc/kubernetes/patches'
            }
        }

        config_new = config_new + "---\n" + yaml.dump(init_config, default_flow_style=False)

        control_plane.put(io.StringIO(config_new), '/etc/kubernetes/audit-on-config.yaml', sudo=True)

        kubernetes.create_kubeadm_patches_for_node(cluster, control_plane)

        control_plane.sudo(f"kubeadm init phase control-plane apiserver "
                           f"--config=/etc/kubernetes/audit-on-config.yaml ")

        if cluster.inventory['services']['cri']['containerRuntime'] == 'containerd':
            control_plane.call(utils.wait_command_successful,
                               command="crictl rm -f $(sudo crictl ps --name kube-apiserver -q)")
        else:
            control_plane.call(utils.wait_command_successful,
                               command="docker stop $(sudo docker ps -q -f 'name=k8s_kube-apiserver'"
                                       " | awk '{print $1}')")
        control_plane.call(utils.wait_command_successful, command="kubectl get pod -n kube-system")
        control_plane.sudo("kubeadm init phase upload-config kubeadm "
                           "--config=/etc/kubernetes/audit-on-config.yaml")


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_dns_hostname(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            cluster.log.debug("Changing hostname '%s' = '%s'" % (node.get_host(), node.get_node_name()))
            node.sudo("hostnamectl set-hostname %s" % node.get_node_name())


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_dns_resolv_conf(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    if cluster.inventory["services"].get("resolv.conf") is None:
        cluster.log.debug("Skipped - resolv.conf section not defined in config file")
        return

    system.update_resolv_conf(group, config=cluster.inventory["services"].get("resolv.conf"))
    cluster.log.debug(group.sudo("ls -la /etc/resolv.conf; sudo lsattr /etc/resolv.conf"))


def system_prepare_dns_etc_hosts(cluster: KubernetesCluster) -> None:
    config = system.generate_etc_hosts_config(cluster.inventory, 'etc_hosts')
    config += system.generate_etc_hosts_config(cluster.inventory, 'etc_hosts_generated')

    utils.dump_file(cluster, config, 'etc_hosts')
    cluster.log.debug("\nUploading...")

    group = cluster.nodes['all'].get_final_nodes()

    system.update_etc_hosts(group, config=config)
    cluster.log.debug(group.sudo("ls -la /etc/hosts"))


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_package_manager_configure(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
    if not repositories:
        cluster.log.debug("Skipped - no repositories defined for configuration")
        return

    group.call(packages.backup_repo)
    group.call(packages.add_repo, repo_data=repositories)

    cluster.log.debug("Nodes contain the following repositories:")
    cluster.log.debug(packages.ls_repofiles(group))


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_package_manager_manage_packages(group: NodeGroup) -> None:
    group.call_batch([
        manage_mandatory_packages,
        manage_custom_packages
    ])


def manage_mandatory_packages(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            pkgs: List[str] = []
            for package in cluster.inventory["services"]["packages"]['mandatory'].keys():
                hosts_to_packages = packages.get_association_hosts_to_packages(node, cluster.inventory, package)
                pkgs.extend(next(iter(hosts_to_packages.values()), []))

            if pkgs:
                cluster.log.debug(f"Installing {pkgs} on {node.get_node_name()!r}")
                packages.install(node, include=pkgs, callback=collector)

    return collector.result


def manage_custom_packages(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster

    batch_results: Dict[str, RunnersGroupResult] = {}
    packages_section = cluster.inventory["services"].get("packages", {})
    if packages_section.get("remove", {}).get("include"):
        cluster.log.debug("Running kubemarine.packages.remove: ")
        remove = packages_section['remove']
        batch_results['remove'] = results = packages.remove(
            group, include=remove['include'], exclude=remove.get('exclude'))
        cluster.log.debug(results)

    if packages_section.get("install", {}).get("include"):
        cluster.log.debug("Running kubemarine.packages.install: ")
        install = packages_section['install']
        batch_results['install'] = results = packages.install(
            group, include=install['include'], exclude=install.get('exclude'))
        cluster.log.debug(results)

    if packages_section.get("upgrade", {}).get("include"):
        cluster.log.debug("Running kubemarine.packages.upgrade: ")
        upgrade = packages_section['upgrade']
        batch_results['upgrade'] = results = packages.upgrade(
            group, include=upgrade['include'], exclude=upgrade.get('exclude'))
        cluster.log.debug(results)

    if not batch_results:
        cluster.log.debug("Skipped - no packages configuration defined in config file")
        return None

    any_changes_found = False
    for action, results in batch_results.items():
        cluster.log.verbose('Verifying packages changes after \'%s\' action...' % action)
        for host, result in results.items():
            node = cluster.make_group([host])
            if not packages.no_changes_found(node, action, result):
                cluster.log.verbose('Packages changed at %s' % host)
                any_changes_found = True

    if any_changes_found:
        cluster.log.verbose('Packages changed, scheduling nodes restart...')
        cluster.schedule_cumulative_point(system.reboot_nodes)
    else:
        cluster.log.verbose('No packages changed, nodes restart will not be scheduled')

    return None


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_cri_install(group: NodeGroup) -> None:
    """
    Task which is used to install CRI. Could be skipped, if CRI already installed.
    """
    group.call(cri.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def system_cri_configure(group: NodeGroup) -> None:
    """
    Task which is used to configure CRI. Could be skipped, if CRI already configured.
    """
    group.call(cri.configure)


@_applicable_for_new_nodes_with_roles('all')
def system_prepare_thirdparties(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    if not cluster.inventory['services'].get('thirdparties', {}):
        cluster.log.debug("Skipped - no thirdparties defined in config file")
        return

    group.call(thirdparties.install_all_thirparties)


@_applicable_for_new_nodes_with_roles('balancer')
def deploy_loadbalancer_haproxy_install(group: NodeGroup) -> None:
    group.call(haproxy.install)


def deploy_loadbalancer_haproxy_configure(cluster: KubernetesCluster) -> None:

    if not cluster.inventory['services'].get('loadbalancer', {}) \
            .get('haproxy', {}).get('keep_configs_updated', True):
        cluster.log.debug('Skipped - haproxy balancers configs update manually disabled')
        return

    balancers = cluster.make_group_from_roles(['balancer'])
    if not cluster.make_group_from_roles(['control-plane', 'worker']).get_changed_nodes().is_empty():
        group = balancers.get_final_nodes()
    elif cluster.context['initial_procedure'] != 'remove_node':
        new_nodes = cluster.nodes['all'].get_new_nodes_or_self()
        group = balancers.intersection_group(new_nodes)
    else:
        group = cluster.make_group([])

    if group.is_empty():
        cluster.log.debug('Skipped - no balancers to perform')
        return

    with group.new_executor() as exe:
        exe.group.call_batch([
            haproxy.configure,
            haproxy.override_haproxy18,
        ])

    haproxy.restart(group)


@_applicable_for_new_nodes_with_roles('keepalived')
def deploy_loadbalancer_keepalived_install(group: NodeGroup) -> None:
    group.call(keepalived.install)


def deploy_loadbalancer_keepalived_configure(cluster: KubernetesCluster) -> None:
    # For install procedure, configure all keepalives.
    # If balancer with VRPP IP is added or removed, reconfigure all keepalives
    keepalived_nodes = cluster.make_group_from_roles(['keepalived'])
    if cluster.context['initial_procedure'] != 'install' and keepalived_nodes.get_changed_nodes().is_empty():
        group = cluster.make_group([])
    else:
        group = keepalived_nodes.get_final_nodes()

    if group.is_empty():
        cluster.log.debug('Skipped - no VRRP IPs to perform')
        return

    group.call(keepalived.configure)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_reset(group: NodeGroup) -> None:
    group.call(kubernetes.reset_installation_env)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_install(group: NodeGroup) -> None:
    group.cluster.log.debug("Setting up Kubernetes...")
    group.call(kubernetes.install)


@_applicable_for_new_nodes_with_roles('control-plane', 'worker')
def deploy_kubernetes_prepull_images(group: NodeGroup) -> None:
    group.cluster.log.debug("Prepulling Kubernetes images...")
    group.call(kubernetes.images_grouped_prepull)


def deploy_kubernetes_init(cluster: KubernetesCluster) -> None:
    cluster.nodes['control-plane'].call_batch([
        kubernetes.init_first_control_plane,
        kubernetes.join_other_control_planes
    ])

    if 'worker' in cluster.nodes:
        cluster.nodes['worker'].exclude_group(cluster.nodes['control-plane']) \
            .call(kubernetes.init_workers)

    cluster.nodes['all'].call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])

    kubernetes.schedule_running_nodes_report(cluster)


def deploy_coredns(cluster: KubernetesCluster) -> None:
    config = coredns.generate_configmap(cluster.inventory)

    cluster.log.debug('Applying patch...')
    cluster.log.debug(coredns.apply_patch(cluster))

    cluster.log.debug('Applying configmap...')
    cluster.log.debug(coredns.apply_configmap(cluster, config))


def deploy_plugins(cluster: KubernetesCluster) -> None:
    plugins.install(cluster)


def deploy_accounts(cluster: KubernetesCluster) -> None:
    kubernetes_accounts.install(cluster)


def overview(cluster: KubernetesCluster) -> None:
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
                "configure": system_prepare_audit,
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
            "init": deploy_kubernetes_init,
            "audit": deploy_kubernetes_audit,
        },
        "admission": admission.install,
        "coredns": deploy_coredns,
        "plugins": deploy_plugins,
        "accounts": deploy_accounts
    },
    "overview": overview
})

cumulative_points = {

    # Reboot and verify that the most crucial system settings are applied on boot.
    # This is done before `prepare.system.audit`.
    system.reboot_nodes: [
        "prepare.system.audit"
    ],
    system.verify_system: [
        "prepare.system.audit"
    ],
    # Some checks can be done only at the end when the necessary services are configured.
    summary.exec_delayed: [
        flow.END_OF_TASKS
    ]
}


def run_tasks(res: DynamicResources, tasks_filter: List[str] = None) -> None:
    flow.run_tasks(res, tasks, cumulative_points=cumulative_points, tasks_filter=tasks_filter)


class InstallAction(Action):
    def __init__(self) -> None:
        super().__init__('install')
        self.target_version = "not supported"

    def run(self, res: DynamicResources) -> None:
        self.target_version = kubernetes.get_initial_kubernetes_version(res.raw_inventory())
        kubernetes.verify_supported_version(self.target_version, res.logger())

        run_tasks(res)


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for installing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_tasks_flow_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='install')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    install = InstallAction()
    flow_ = flow.ActionsFlow([install])
    result = flow_.run_flow(context)

    kubernetes.verify_supported_version(install.target_version, result.logger)


if __name__ == '__main__':
    main()
