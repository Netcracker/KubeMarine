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

import os.path
from collections import OrderedDict
import fabric
import yaml
import ruamel.yaml
import io
from kubemarine.core.errors import KME
from kubemarine import system, sysctl, haproxy, keepalived, kubernetes, plugins, \
    kubernetes_accounts, selinux, thirdparties, psp, audit, coredns, cri, packages, apparmor
from kubemarine.core import flow, utils
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.yaml_merger import default_merger

def system_prepare_check_sudoer(cluster):
    for host, node_context in cluster.context['nodes'].items():
        if node_context['online'] and node_context['hasroot']:
            cluster.log.debug("%s online and has root" % host)
        else:
            raise KME("KME0005", hostname=host)


def system_prepare_check_system(cluster):
    group = cluster.nodes['all'].get_new_nodes_or_self()
    cluster.log.debug(system.detect_os_family(cluster, suppress_exceptions=True))
    for address, context in cluster.context["nodes"].items():
        if address not in group.nodes or not context.get('os'):
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


def system_prepare_system_chrony(cluster):
    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') is None:
        cluster.log.debug("Skipped - NTP servers from chrony is not defined in config file")
        return
    cluster.nodes['all'].get_new_nodes_or_self().call(system.configure_chronyd)


def system_prepare_system_timesyncd(cluster):
    if not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') and \
            not cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP'):
        cluster.log.debug("Skipped - NTP servers from timesyncd is not defined in config file")
        return
    cluster.nodes['all'].get_new_nodes_or_self().call(system.configure_timesyncd)


def system_prepare_system_sysctl(cluster):
    if cluster.inventory['services'].get('sysctl') is None or not cluster.inventory['services']['sysctl']:
        cluster.log.debug("Skipped - sysctl is not defined or empty in config file")
        return
    cluster.nodes['all'].get_new_nodes_or_self().call_batch([
        sysctl.configure,
        sysctl.reload,
    ])


def system_prepare_system_setup_selinux(cluster):
    cluster.nodes['all'].get_new_nodes_or_self().call(selinux.setup_selinux)


def system_prepare_system_setup_apparmor(cluster):
    cluster.nodes['all'].get_new_nodes_or_self().call(apparmor.setup_apparmor)


def system_prepare_system_disable_firewalld(cluster):
    cluster.nodes['all'].get_new_nodes_or_self().call(system.disable_firewalld)


def system_prepare_system_disable_swap(cluster):
    cluster.nodes['all'].get_new_nodes_or_self().call(system.disable_swap)


def system_prepare_system_modprobe(cluster):
    cluster.nodes['all'].get_new_nodes_or_self().call(system.setup_modprobe)


def system_install_audit(cluster):
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker')).get_new_nodes_or_self()
    cluster.log.debug(group.call(audit.install))


def system_prepare_audit_daemon(cluster):
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker')).get_new_nodes_or_self()
    cluster.log.debug(group.call(audit.apply_audit_rules))

def system_prepare_policy(cluster):
    """
    Task generates rules for logging kubernetes
    """

    audit_log_dir = os.path.dirname(cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']['audit-log-path'])
    audit_policy_dir = os.path.dirname(cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']['audit-policy-file'])
    cluster.nodes['master'].run(f"sudo mkdir -p {audit_log_dir} && sudo mkdir -p {audit_policy_dir}")
    audit_file_name = cluster.inventory['services']['kubeadm']['apiServer']['extraArgs']['audit-policy-file']
    policy_config = cluster.inventory['services']['audit'].get('cluster_policy')

    if policy_config:
        policy_config_file = yaml.dump(policy_config)
        utils.dump_file(cluster, policy_config_file, 'audit-policy.yaml')
        cluster.nodes['master'].put(io.StringIO(policy_config_file), audit_file_name, sudo=True, backup=True)

    else:
        cluster.log.debug("Audit cluster policy config is empty, nothing will be configured ")

def kubernetes_audit_on(cluster):
    """
    Task including audit
    """
    for master in cluster.nodes['master'].get_ordered_members_list():
        config_new = (kubernetes.get_kubeadm_config(cluster.inventory))
        master.put(io.StringIO(config_new), '/etc/kubernetes/audit-on-config.yaml', sudo=True)
        master.sudo("kubeadm init phase control-plane apiserver --config=/etc/kubernetes/audit-on-config.yaml")
        continue


    cluster.nodes['master'].call(utils.wait_command_successful,
                                 command="kubectl delete pod -n kube-system "
                                         "$(sudo kubectl get pod -n kube-system "
                                         "| grep 'kube-apiserver' | awk '{ print $1 }')")
    cluster.nodes['master'].call(utils.wait_command_successful, command="kubectl get pod -A")

def system_prepare_dns_hostname(cluster):
    with RemoteExecutor(cluster):
        for node in cluster.nodes['all'].get_new_nodes_or_self().get_ordered_members_list(provide_node_configs=True):
            cluster.log.debug("Changing hostname '%s' = '%s'" % (node["connect_to"], node["name"]))
            node["connection"].sudo("hostnamectl set-hostname %s" % node["name"])


def system_prepare_dns_resolv_conf(cluster):
    if cluster.inventory["services"].get("resolv.conf") is None:
        cluster.log.debug("Skipped - resolv.conf section not defined in config file")
        return

    group = cluster.nodes['all'].get_new_nodes_or_self()

    system.update_resolv_conf(group, config=cluster.inventory["services"].get("resolv.conf"))
    cluster.log.debug(group.sudo("ls -la /etc/resolv.conf; sudo lsattr /etc/resolv.conf"))


def system_prepare_dns_etc_hosts(cluster):
    config = system.generate_etc_hosts_config(cluster.inventory, cluster)

    utils.dump_file(cluster, config, 'etc_hosts')
    cluster.log.debug("\nUploading...")

    group = cluster.nodes['all'].get_final_nodes()

    system.update_etc_hosts(group, config=config)
    cluster.log.debug(group.sudo("ls -la /etc/hosts"))


def system_prepare_package_manager_configure(cluster):
    repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
    if not repositories:
        cluster.log.debug("Skipped - no repositories defined for configuration")
        return

    group = cluster.nodes['all'].get_new_nodes_or_self()

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


def system_prepare_package_manager_manage_packages(cluster):
    if not cluster.inventory["services"].get("packages", {}):
        cluster.log.debug("Skipped - no packages configuration defined in config file")
        return

    batch_tasks = []
    batch_parameters = {}

    if cluster.inventory["services"]["packages"].get("remove", []):
        batch_tasks.append(packages.remove)
        batch_parameters["kubemarine.packages.remove"] = {
            "include": cluster.inventory["services"]["packages"]['remove']['include'],
            "exclude": cluster.inventory["services"]["packages"]['remove'].get('exclude')
        }

    if cluster.inventory["services"]["packages"].get("install", []):
        batch_tasks.append(packages.install)
        batch_parameters["kubemarine.packages.install"] = {
            "include": cluster.inventory["services"]["packages"]['install']['include'],
            "exclude": cluster.inventory["services"]["packages"]['install'].get('exclude')
        }

    if cluster.inventory["services"]["packages"].get("upgrade", []):
        batch_tasks.append(packages.upgrade)
        batch_parameters["kubemarine.packages.upgrade"] = {
            "include": cluster.inventory["services"]["packages"]['upgrade']['include'],
            "exclude": cluster.inventory["services"]["packages"]['upgrade'].get('exclude')
        }

    try:
        batch_results = cluster.nodes['all'].get_new_nodes_or_self().call_batch(batch_tasks, **batch_parameters)
    except fabric.group.GroupException:
        cluster.log.verbose('Exception occurred! Trying to handle is there anything updated or not...')
        # todo develop cases when we can continue even if exception occurs
        raise

    any_changes_found = False
    for action, results in batch_results.items():
        cluster.log.verbose('Verifying packages changes after \'%s\' action...' % action)
        for conn, result in results.items():
            if "Nothing to do" not in result.stdout:
                cluster.log.verbose('Packages changed at %s' % conn.host)
                any_changes_found = True

    if any_changes_found:
        cluster.log.verbose('Packages changed, scheduling nodes restart...')
        cluster.schedule_cumulative_point(system.reboot_nodes)
    else:
        cluster.log.verbose('No packages changed, nodes restart will not be scheduled')


def system_cri_install(cluster):
    """
    Task which is used to install CRI. Could be skipped, if CRI already installed.
    """
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node':
        group = group.get_new_nodes()

    group.call(cri.install)


def system_cri_configure(cluster):
    """
    Task which is used to configure CRI. Could be skipped, if CRI already configured.
    """
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node':
        group = group.get_new_nodes()

    group.call(cri.configure)


def system_prepare_thirdparties(cluster):
    if not cluster.inventory['services'].get('thirdparties', {}):
        cluster.log.debug("Skipped - no thirdparties defined in config file")
        return

    cluster.nodes['all'].get_new_nodes_or_self().call(thirdparties.install_all_thirparties)


def deploy_loadbalancer_haproxy_install(cluster):
    group = None
    if "balancer" in cluster.nodes:

        group = cluster.nodes['balancer']

        if cluster.context['initial_procedure'] == 'add_node':
            group = cluster.nodes['balancer'].get_new_nodes()

    if group is None or group.is_empty():
        cluster.log.debug('Skipped - no balancers to perform')
        return

    group.call(haproxy.install)


def deploy_loadbalancer_haproxy_configure(cluster):
    group = None
    if "balancer" in cluster.nodes:

        if cluster.context['initial_procedure'] != 'remove_node':
            group = cluster.nodes['balancer'].get_new_nodes_or_self()

        if not cluster.nodes['master'].include_group(cluster.nodes.get('worker')).get_changed_nodes().is_empty():
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


def deploy_kubernetes_reset(cluster):
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node' and group.get_new_nodes().is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.get_new_nodes_or_self().call(kubernetes.reset_installation_env)


def deploy_kubernetes_install(cluster):
    cluster.log.debug("Setting up Kubernetes...")

    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node' and group.get_new_nodes().is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.get_new_nodes_or_self().call(kubernetes.install)




def deploy_kubernetes_prepull_images(cluster):
    cluster.log.debug("Prepulling Kubernetes images...")

    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node' and group.get_new_nodes().is_empty():
        cluster.log.debug("No kubernetes nodes to perform")
        return

    group.get_new_nodes_or_self().call(kubernetes.images_grouped_prepull)


def deploy_kubernetes_init(cluster):
    group = cluster.nodes['master'].include_group(cluster.nodes.get('worker'))

    if cluster.context['initial_procedure'] == 'add_node' and group.get_new_nodes().is_empty():
        cluster.log.debug("No kubernetes nodes for installation")
        return

    cluster.nodes['master'].get_new_nodes_or_self().call_batch([
        kubernetes.init_first_master,
        kubernetes.join_other_masters
    ])

    if 'worker' in cluster.nodes:
        cluster.nodes.get('worker').get_new_nodes_or_self().new_group(
            apply_filter=lambda node: 'master' not in node['roles']) \
            .call(kubernetes.init_workers)

    cluster.nodes['all'].get_new_nodes_or_self().call_batch([
        kubernetes.apply_labels,
        kubernetes.apply_taints
    ])



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
    master = cluster.nodes["master"].get_final_nodes().get_first_member()
    cluster.log.debug("\nNAMESPACES:")
    master.sudo("kubectl get namespaces", hide=False)
    cluster.log.debug("\nNODES:")
    master.sudo("kubectl get nodes -o wide", hide=False)
    cluster.log.debug("\nPODS:")
    master.sudo("kubectl get pods -A -o=wide", hide=False)
    cluster.log.debug("\nREPLICA SETS:")
    master.sudo("kubectl get rs -A", hide=False)
    cluster.log.debug("\nDAEMON SETS:")
    master.sudo("kubectl get ds -A", hide=False)
    cluster.log.debug("\nSERVICES:")
    master.sudo("kubectl get svc -A -o wide", hide=False)
    cluster.log.debug("\nINGRESS:")
    master.sudo("kubectl get ing -A -o wide", hide=False)
    cluster.log.debug("\nDESCRIPTION:")
    master.sudo("kubectl describe nodes", hide=False)
    cluster.log.debug("\n")
    master.sudo("kubectl cluster-info", hide=False, warn=True)


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
            "init": deploy_kubernetes_init,
            "kubernetes_audit": kubernetes_audit_on

        },
        "psp": psp.install_psp_task,
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
    'kubemarine.system.reboot_nodes': [
        "prepare.system.sysctl"
    ],
    'kubemarine.system.verify_system': [
        "prepare.system.sysctl"
    ]

}


def main(cli_arguments=None):
    cli_help = '''
    Script for installing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_parser(cli_help)

    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    args = flow.parse_args(parser, cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    with open(args.config, 'r') as stream:
        cluster_yml = yaml.safe_load(stream)
    verification_version_result = ""
    if (cluster_yml.get("services", {})
            and cluster_yml["services"].get("kubeadm", {})
            and cluster_yml["services"]["kubeadm"].get("kubernetesVersion")):
        target_version = cluster_yml["services"]["kubeadm"].get("kubernetesVersion")
        verification_version_result = kubernetes.verify_target_version(target_version)

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        flow.create_context(args, procedure='install',
                            included_tasks=defined_tasks, excluded_tasks=defined_excludes),
        cumulative_points=cumulative_points
    )
    if verification_version_result:
        print(verification_version_result)


if __name__ == '__main__':
    main()
