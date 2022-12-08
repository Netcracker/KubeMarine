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

import configparser
import io
import paramiko
import re
import socket
import time
from copy import deepcopy
from typing import Dict

from dateutil.parser import parse
import fabric
import invoke
import yaml

from kubemarine import selinux, kubernetes
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroupResult, NodeGroup
from kubemarine.core.yaml_merger import default_merger
from kubemarine.core.annotations import restrict_empty_group


def verify_inventory(inventory, cluster):

    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') \
        and (cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') or
             cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP')):
        raise Exception('chrony and timesyncd configured both at the same time')

    # TODO: Add validation that selinux and apparmor are not enabled at the same time

    return inventory


def enrich_inventory(inventory, cluster):
    if inventory['services'].get('packages'):
        for _type in ['install', 'upgrade', 'remove']:
            if inventory['services']['packages'].get(_type) is not None:
                if isinstance(inventory['services']['packages'][_type], list):
                    inventory['services']['packages'][_type] = {
                        'include': inventory['services']['packages'][_type]
                    }
                for __type in ['include', 'exclude']:
                    if inventory['services']['packages'][_type].get(__type) is not None:
                        if not isinstance(inventory['services']['packages'][_type][__type], list):
                            raise Exception('Packages %s section in configfile has invalid type. '
                                            'Expected \'list\', but found \'%s\''
                                            % (__type, type(inventory['services']['packages'][_type][__type])))
                        if not inventory['services']['packages'][_type][__type]:
                            raise Exception('Packages %s section contains empty \'%s\' definition. ' % (__type, __type))
                    elif __type == 'include':
                        if _type != 'install':
                            inventory['services']['packages'][_type]['include'] = ['*']
                        else:
                            raise Exception('Definition \'include\' is missing in \'install\' packages section, '
                                            'but should be specified.')

    if inventory['services'].get('etc_hosts'):

        control_plain = inventory['control_plain']['internal']

        control_plain_names = inventory['services']['etc_hosts'].get(control_plain, [])
        control_plain_names.append(cluster.inventory['cluster_name'])
        control_plain_names.append('control-plain')
        inventory['services']['etc_hosts'][control_plain] = control_plain_names

        for node in cluster.inventory['nodes']:
            if 'remove_node' in node['roles']:
                continue

            internal_node_ip_names = inventory['services']['etc_hosts'].get(node['internal_address'], [])
            internal_node_ip_names.append("%s.%s" % (node['name'], cluster.inventory['cluster_name']))
            internal_node_ip_names.append(node['name'])
            inventory['services']['etc_hosts'][node['internal_address']] = internal_node_ip_names

            if node.get('address'):
                external_node_ip_names = inventory['services']['etc_hosts'].get(node['address'], [])
                external_node_ip_names.append("%s-external.%s" % (node['name'], cluster.inventory['cluster_name']))
                external_node_ip_names.append(node['name'] + "-external")
                inventory['services']['etc_hosts'][node['address']] = external_node_ip_names

            uniq_node_hostnames = list(set(inventory['services']['etc_hosts'][node['address']]))
            inventory['services']['etc_hosts'][node['address']] = uniq_node_hostnames


    return inventory


def enrich_upgrade_inventory(inventory, cluster):
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory

    # validate all packages sections in procedure inventory
    with open(utils.get_resource_absolute_path('resources/configurations/defaults.yaml', script_relative=True), 'r') \
            as stream:
        base_associations = yaml.safe_load(stream)["services"]["packages"]["associations"][get_os_family(cluster)]

    cluster_associations = deepcopy(cluster.inventory["services"]["packages"]["associations"])
    previous_ver = cluster.context["initial_kubernetes_version"]
    upgrade_plan = cluster.procedure_inventory.get('upgrade_plan')
    for version in upgrade_plan:
        upgrade_associations = cluster.procedure_inventory.get(version, {}).get("packages", {}).get("associations", {})
        for package in get_system_packages(cluster):
            if base_associations[package]["package_name"] != cluster_associations[package]["package_name"] \
                    and not upgrade_associations.get(package, {}).get("package_name"):
                raise Exception(f"Associations are redefined for {package} in cluster.yaml for version {previous_ver}, "
                                f"but not present in procedure inventory for version {version}. "
                                f"Please, specify required associations explicitly in procedure inventory "
                                f"for all versions since {previous_ver}.")
            if upgrade_associations.get(package, {}).get("package_name"):
                cluster_associations[package]["package_name"] = upgrade_associations[package]["package_name"]
        previous_ver = version

    upgrade_required = get_system_packages_for_upgrade(cluster)
    cluster.context["packages"] = {"upgrade_required": upgrade_required}

    upgrade_ver = cluster.context["upgrade_version"]
    packages_section = cluster.procedure_inventory.get(upgrade_ver, {}).get("packages")
    if packages_section:
        default_merger.merge(inventory["services"]["packages"], packages_section)

    return inventory


def get_system_packages_for_upgrade(cluster):
    upgrade_ver = cluster.context["upgrade_version"]
    previous_ver = cluster.context["initial_kubernetes_version"]
    compatibility = cluster.globals["compatibility_map"]["software"]

    # handle special cases in which upgrade is not required for particular package
    cluster_associations = cluster.inventory["services"]["packages"]["associations"]
    upgrade_associations = cluster.procedure_inventory.get(upgrade_ver, {}).get("packages", {}).get("associations", {})
    system_packages = get_system_packages(cluster)
    upgrade_required = list(system_packages)
    for package in system_packages:
        defined_association = upgrade_associations.get(package, {}).get("package_name")
        if defined_association and defined_association == cluster_associations[package]['package_name']:
            # case 1: package_name is defined in upgrade inventory but is equal to one already defined in cluster.yaml
            upgrade_required.remove(package)
        elif compatibility.get(package) and compatibility[package][upgrade_ver] == compatibility[package][previous_ver] \
                and not defined_association:
            # case 2: package_name is not defined in upgrade inventory and default versions are equal
            upgrade_required.remove(package)

    # all other packages should be updated
    return upgrade_required


def get_system_packages(cluster):
    return ["haproxy", "keepalived", cluster.inventory['services']['cri']['containerRuntime']]


def fetch_os_versions(cluster: KubernetesCluster):
    group = cluster.nodes['all'].get_accessible_nodes()
    '''
    For Red Hat, CentOS, Oracle Linux, and Ubuntu information in /etc/os-release /etc/redhat-release is sufficient but,
    Debian stores the full version in a special file. sed transforms version string, eg 10.10 becomes DEBIAN_VERSION="10.10"  
    '''

    return group.run(
        "cat /etc/*elease; cat /etc/debian_version 2> /dev/null | sed 's/\\(.\\+\\)/DEBIAN_VERSION=\"\\1\"/' || true")


def detect_os_family(cluster):
    results = fetch_os_versions(cluster)

    for connection, result in results.items():
        stdout = result.stdout.lower()

        version = None
        versions = []
        lines = ''

        version_regex = re.compile("\\s\\d*\\.\\d*", re.M)
        for line in stdout.split("\n"):
            if 'centos' in line or 'rhel' in line:
                # CentOS and Red Hat have a major version in VERSION_ID string
                matches = re.findall(version_regex, line)
                if matches:
                    version = matches[0].strip()
            if '=' in line:
                lines += line + "\n"

        os_release = configparser.ConfigParser()
        os_release.read_string("[system]\n" + lines)
        name = os_release.get("system", "id").replace('"', '')
        if version is None:
            if name == 'debian':
                version = os_release.get("system", "debian_version").replace('"', '')
            else:
                # Oracle Linux and Ubuntu have full version in VERSION_ID string
                version = os_release.get("system", "version_id").replace('"', '')

        cluster.log.debug("Distribution: %s; Version: %s" % (name, version))

        if name in cluster.globals["compatibility_map"]["distributives"]:
            os_family_list = cluster.globals["compatibility_map"]["distributives"][name]
            for os_family_item in os_family_list:
                versions.extend(os_family_item["versions"])
                if version in versions:
                    os_family = os_family_item["os_family"]
                    versions = []
                    break
                else:
                    os_family = 'unknown'
        else:
            os_family = 'unsupported'

        cluster.log.debug("OS family: %s" % os_family)

        cluster.context["nodes"][connection.host]["os"] = {
            'name': name,
            'version': version,
            'family': os_family
        }

    cluster.context["os"] = cluster.nodes["all"].get_accessible_nodes().get_nodes_os(suppress_exceptions=True)


def get_os_family(cluster: KubernetesCluster) -> str:
    """
    Returns common OS family name from remote hosts.
    :param cluster: Cluster object where OS family is detected.
    :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "multiple", "unknown".
    """
    # OS family is always not None,
    # because it is either detected during cluster initialization, or there are no accessible nodes to detect it.
    return cluster.context.get("os")


def get_compatibility_version_key(cluster: KubernetesCluster) -> str or None:
    """
    Get os-specific version key to be used in software compatibility map.
    :param cluster: Cluster object for which to resolve compatibility version key.
    :return: String to use as version key. None if OS is unknown or multiple OS present.
    """
    """
    Return os-specific version compatibility key.
    If OS is unknown or multiple OS, then returns None.
    """
    os = get_os_family(cluster)
    if os == "rhel":
        return "version_rhel"
    elif os == "rhel8":
        return "version_rhel8"
    elif os == "debian":
        return "version_debian"
    else:
        return None


def is_multiple_os_detected(cluster):
    return get_os_family(cluster) == 'multiple'


def update_resolv_conf(group, config=None):
    if config is None:
        raise Exception("Data can't be empty")

    # TODO: Use Jinja template
    buffer = io.StringIO()
    if config.get("search") is not None:
        buffer.write("search %s\n" % config["search"])
    if config.get("nameservers") is not None:
        for address in config.get("nameservers"):
            buffer.write("nameserver %s\n" % address)

    utils.dump_file(group.cluster, buffer, 'resolv.conf')

    group.put(buffer, "/etc/resolv.conf", backup=True, immutable=True, sudo=True, hide=True)


def generate_etc_hosts_config(inventory, cluster=None):
    result = ""

    max_len_ip = 0

    ignore_ips = []
    if cluster and cluster.context['initial_procedure'] == 'remove_node':
        for removal_node in cluster.procedure_inventory.get("nodes"):
            if isinstance(removal_node, str):
                removal_node_name = removal_node
            elif isinstance(removal_node, dict) and removal_node.get('name'):
                removal_node_name = removal_node['name']
            else:
                raise Exception('Invalid node specification in procedure.yaml')
            for node in inventory['nodes']:
                if node['name'] == removal_node_name:
                    if node.get('address'):
                        ignore_ips.append(node['address'])
                    if node.get('internal_address'):
                        ignore_ips.append(node['internal_address'])

    ignore_ips = list(set(ignore_ips))

    for ip in list(inventory['services']['etc_hosts'].keys()):
        if len(ip) > max_len_ip:
            max_len_ip = len(ip)

    for ip, names in inventory['services']['etc_hosts'].items():
        if isinstance(names, list):
            # remove records with empty values from list
            names = list(filter(len, names))
            # if list is empty, then skip
            if not names:
                continue
            names = " ".join(names)
        if ip not in ignore_ips:
            result += "%s%s  %s\n" % (ip, " " * (max_len_ip - len(ip)), names)

    return result


def update_etc_hosts(group, config=None):
    if config is None:
        raise Exception("Data can't be empty")
    utils.dump_file(group.cluster, config, 'etc_hosts')
    group.put(io.StringIO(config), "/etc/hosts", backup=True, sudo=True, hide=True)


def stop_service(group: NodeGroup, name: str) -> NodeGroupResult:
    return group.sudo('systemctl stop %s' % name)


def start_service(group: NodeGroup, name: str) -> NodeGroupResult:
    return group.sudo('systemctl start %s' % name)


def restart_service(group, name=None):
    if name is None:
        raise Exception("Service name can't be empty")
    return group.sudo('systemctl restart %s' % name)


def enable_service(group, name=None, now=True):
    if name is None:
        raise Exception("Service name can't be empty")

    cmd = 'systemctl enable %s' % name
    if now:
        cmd = cmd + " --now"
    return group.sudo(cmd)


def disable_service(group, name=None, now=True):
    if name is None:
        raise Exception("Service name can't be empty")

    cmd = 'systemctl disable %s' % name
    if now:
        cmd = cmd + " --now"
    return group.sudo(cmd)


def patch_systemd_service(group: NodeGroup, service_name, patch_source):
    group.sudo(f"mkdir -p /etc/systemd/system/{service_name}.service.d")
    group.put(patch_source, f"/etc/systemd/system/{service_name}.service.d/{service_name}.conf",
              sudo=True, binary=False)
    group.sudo("systemctl daemon-reload")

def fetch_firewalld_status(group: NodeGroup) -> NodeGroupResult:
    return group.sudo("systemctl status firewalld", warn=True)

def is_firewalld_disabled(group, check_post=None):

    result = fetch_firewalld_status(group)

    disabled_status = False
    restart_node = False
    nodes = {}

    for node_result in list(result.values()):
        if node_result.return_code == 4:
            disabled_status = True
        elif node_result.return_code == 3 and "disabled" in node_result.stdout:
            disabled_status = True
        elif node_result.return_code not in [3,4] or "disabled" not in node_result.stdout and check_post != True:
            nodes[node_result.connection.host] = node_result.connection
            disabled_status = False
            restart_node = True

    if check_post == True:
        return disabled_status, result

    return disabled_status, result, nodes, restart_node

def disable_firewalld(group):
    log = group.cluster.log

    already_disabled, result, nodes, restart_node = is_firewalld_disabled(group)

    if already_disabled and restart_node != True:
        log.debug("Skipped - FirewallD already disabled or not installed")
        return result
    if restart_node:
        disable_nodes = NodeGroup(nodes, group.cluster)
        result = disable_service(disable_nodes, name='firewalld', now=True)
        group.cluster.schedule_cumulative_point(reboot_nodes)
        group.cluster.schedule_cumulative_point(verify_system)
    return result


def is_swap_disabled(group):
    result = group.sudo("cat /proc/swaps", warn=True)
    disabled_status = True

    for node_result in list(result.values()):
        # is there any other lines excluding first head line?
        if node_result.stdout.strip().split('\n')[1:]:
            disabled_status = False

    return disabled_status, result


def disable_swap(group):


    group.cluster.schedule_cumulative_point(reboot_nodes)
    group.cluster.schedule_cumulative_point(verify_system)

    log = group.cluster.log

    already_disabled, result = is_swap_disabled(group)

    if already_disabled:
        log.debug("Skipped - swap already disabled")
        return result

    log.verbose("Switching swap off...")

    group.sudo('swapoff -a', warn=True)
    group.sudo('sed -i.bak \'/swap/d\' /etc/fstab', warn=True)

    group.cluster.schedule_cumulative_point(reboot_nodes)
    group.cluster.schedule_cumulative_point(verify_system)


def reboot_nodes(group, try_graceful=None, cordone_on_graceful=True):
    log = group.cluster.log

    if try_graceful is None:
        if 'controlplain_uri' not in group.cluster.context.keys():
            kubernetes.is_cluster_installed(group.cluster)

    graceful_reboot = try_graceful is True or \
                      (try_graceful is None and group.cluster.context['controlplain_uri'] is not None)

    if not graceful_reboot:
        return perform_group_reboot(group)

    log.verbose('Graceful reboot required')

    first_control_plane = group.cluster.nodes['control-plane'].get_first_member()
    results = NodeGroupResult(group.cluster)

    for node in group.get_ordered_members_list(provide_node_configs=True):
        cordon_required = cordone_on_graceful and ('control-plane' in node['roles'] or 'worker' in node['roles'])
        if cordon_required:
            res = first_control_plane.sudo(
                kubernetes.prepare_drain_command(node, group.cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                                 group.cluster.globals, False, group.cluster.nodes), warn=True)
            log.verbose(res)
        log.debug(f'Rebooting node "{node["name"]}"')
        raw_results = perform_group_reboot(node['connection'])
        if cordon_required:
            res = first_control_plane.sudo(f'kubectl uncordon {node["name"]}', warn=True)
            log.verbose(res)
        results.update(raw_results)

    return results


def get_reboot_history(group: NodeGroup):
    return group.sudo('last reboot')


def perform_group_reboot(group: NodeGroup):
    log = group.cluster.log

    initial_boot_history = get_reboot_history(group)
    result = group.sudo(group.cluster.globals['nodes']['boot']['reboot_command'], warn=True)
    log.debug("Waiting for boot up...")
    group.wait_for_reboot(initial_boot_history)
    return result


def reload_systemctl(group):
    return group.sudo('systemctl daemon-reload')


def add_to_path(group, string):
    # TODO: Also update PATH in ~/.bash_profile
    group.sudo("export PATH=$PATH:%s" % string)

def configure_chronyd(group, retries=60):
    cluster = group.cluster
    log = cluster.log
    chronyd_config = ''

    for server in cluster.inventory['services']['ntp']['chrony']['servers']:
        chronyd_config += "server " + server + "\n"

    if cluster.inventory['services']['ntp']['chrony'].get('makestep'):
        chronyd_config += "\nmakestep " + cluster.inventory['services']['ntp']['chrony']['makestep']

    if cluster.inventory['services']['ntp']['chrony'].get('rtcsync', False):
        chronyd_config += "\nrtcsync"

    utils.dump_file(cluster, chronyd_config, 'chrony.conf')
    group.put(io.StringIO(chronyd_config), '/etc/chrony.conf', backup=True, sudo=True)
    group.sudo('systemctl restart chronyd')
    while retries > 0:
        log.debug("Waiting for time sync, retries left: %s" % retries)
        results = group.sudo('chronyc tracking && sudo chronyc sources')
        if results.stdout_contains("Normal"):
            log.verbose("NTP service reported successful time synchronization, validating...")

            current_node_time, nodes_time, time_diff = get_nodes_time(group)
            if time_diff > cluster.globals['nodes']['max_time_difference']:
                log.debug("Time is not synced yet")
                log.debug(results)
            else:
                log.debug("Time synced!")
                return results

        else:
            log.debug("Time is not synced yet")
            log.debug(results)
        time.sleep(1)
        retries -= 1

    raise Exception("Time not synced, but timeout is reached")


def configure_timesyncd(group, retries=120):
    cluster = group.cluster
    log = cluster.log
    timesyncd_config = ''

    for section, options in cluster.inventory['services']['ntp']['timesyncd'].items():
        timesyncd_config += '[%s]' % section
        for option_name, option_value in options.items():
            if isinstance(option_value, list):
                option_value_str = " ".join(option_value)
            else:
                option_value_str = str(option_value)
            timesyncd_config += '\n%s=%s' % (option_name, option_value_str)
        timesyncd_config += '\n\n'

    utils.dump_file(cluster, timesyncd_config, 'timesyncd.conf')
    group.put(io.StringIO(timesyncd_config), '/etc/systemd/timesyncd.conf', backup=True, sudo=True)
    res = group.sudo('timedatectl set-ntp true '
                     '&& sudo systemctl enable --now systemd-timesyncd.service '
                     '&& sudo systemctl restart systemd-timesyncd.service '
                     '&& sudo systemctl status systemd-timesyncd.service')
    log.verbose(res)
    while retries > 0:
        log.debug("Waiting for time sync, retries left: %s" % retries)
        results = group.sudo('timedatectl timesync-status && sudo timedatectl status')
        if results.stdout_contains("synchronized: yes"):
            log.verbose("NTP service reported successful time synchronization, validating...")

            current_node_time, nodes_time, time_diff = get_nodes_time(group)
            if time_diff > cluster.globals['nodes']['max_time_difference']:
                log.debug("Time is not synced yet")
                log.debug(results)
            else:
                log.debug("Time synced!")
                return results

        else:
            log.debug("Time is not synced yet")
            log.debug(results)
        time.sleep(1)
        retries -= 1

    raise Exception("Time not synced, but timeout is reached")


def setup_modprobe(group):
    log = group.cluster.log

    if group.cluster.inventory['services'].get('modprobe') is None \
            or not group.cluster.inventory['services']['modprobe']:
        log.debug('Skipped - no modprobe configs in inventory')
        return

    is_valid, result = is_modprobe_valid(group)

    if is_valid:
        log.debug("Skipped - all necessary kernel modules are presented")
        return result

    config = ''
    for module_name in group.cluster.inventory['services']['modprobe']:
        module_name = module_name.strip()
        if module_name is not None and module_name != '':
            config += module_name + "\n"

    log.debug("Uploading config...")
    utils.dump_file(group.cluster, config, 'modprobe_predefined.conf')
    group.put(io.StringIO(config), "/etc/modules-load.d/predefined.conf", backup=True, sudo=True, hide=True)

    group.cluster.schedule_cumulative_point(reboot_nodes)
    group.cluster.schedule_cumulative_point(verify_system)


def is_modprobe_valid(group):
    log = group.cluster.log

    verify_results = group.sudo("lsmod", warn=True)
    is_valid = True

    for module_name in group.cluster.inventory['services']['modprobe']:
        for conn, result in verify_results.items():
            if module_name not in result.stdout:
                log.debug('Kernel module %s not found at %s' % (module_name, conn.host))
                is_valid = False

    return is_valid, verify_results


def verify_system(group):
    log = group.cluster.log
    # this method handles clusters with multiple is, suppress exceptions enabled
    os_family = group.get_nodes_os(suppress_exceptions=True)

    if os_family in ['rhel', 'rhel8'] and group.cluster.is_task_completed('prepare.system.setup_selinux'):
        log.debug("Verifying Selinux...")
        selinux_configured, selinux_result, selinux_parsed_result = \
            selinux.is_config_valid(group,
                                    state=selinux.get_expected_state(group.cluster.inventory),
                                    policy=selinux.get_expected_policy(group.cluster.inventory),
                                    permissive=selinux.get_expected_permissive(group.cluster.inventory))
        log.debug(selinux_result)
        if not selinux_configured:
            raise Exception("Selinux is still not configured")
    else:
        log.debug('Selinux verification skipped - origin task was not completed')

    # TODO: support apparmor validation
    # if group.cluster.is_task_completed('prepare.system.setup_apparmor') and os_family == 'debian':
    #     log.debug("Verifying Apparmor...")
    #     if not apparmor_configured:
    #         raise Exception("Selinux is still not configured")
    # else:
    #     log.debug('Apparmor verification skipped - origin task was not completed')

    if group.cluster.is_task_completed('prepare.system.disable_firewalld'):
        log.debug("Verifying FirewallD...")
        firewalld_disabled, firewalld_result = is_firewalld_disabled(group,check_post=True)
        log.debug(firewalld_result)
        if not firewalld_disabled:
            raise Exception("FirewallD is still enabled")

        else:
            log.debug("FirewallD disabled")
    else:
        log.debug('FirewallD verification skipped - origin disable task was not completed')

    if group.cluster.is_task_completed('prepare.system.disable_swap'):
        log.debug("Verifying swap...")
        swap_disabled, swap_result = is_swap_disabled(group)
        log.debug(swap_result)
        if not swap_disabled:
            raise Exception("Swap is still enabled")
    else:
        log.debug('Swap verification skipped - origin disable task was not completed')

    if group.cluster.is_task_completed('prepare.system.modprobe'):
        log.debug("Verifying modprobe...")
        modprobe_valid, modprobe_result = is_modprobe_valid(group)
        log.debug(modprobe_result)
        if not modprobe_valid:
            raise Exception("Required kernel modules are not presented")
    else:
        log.debug('Modprobe verification skipped - origin setup task was not completed')


def detect_active_interface(cluster: KubernetesCluster):
    group = cluster.nodes['all'].get_accessible_nodes()
    with RemoteExecutor(cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            detect_interface_by_address(node['connection'], node['internal_address'])
    for cxn, host_results in exe.get_last_results().items():
        try:
            interface = list(host_results.values())[0].stdout.strip()
        except Exception:
            interface = None
        cluster.context['nodes'][cxn.host]['active_interface'] = interface

    return exe.get_last_results_str()


def detect_interface_by_address(group: NodeGroup, address: str):
    return group.run("/usr/sbin/ip -o a | grep %s | awk '{print $2}'" % address)


def _detect_nodes_access_info(cluster: KubernetesCluster):
    nodes_context = cluster.context['nodes']
    hosts_unknown_status = [host for host, node_context in nodes_context.items() if 'access' not in node_context]
    group_unknown_status = cluster.make_group(hosts_unknown_status)
    if group_unknown_status.is_empty():
        return

    check_active_timeout = int(cluster.globals["nodes"]["remove"]["check_active_timeout"])
    exc = None
    try:
        # This should invoke sudo last reboot
        results = group_unknown_status.wait_and_get_boot_history(timeout=check_active_timeout)
    except fabric.group.GroupException as e:
        exc = e
        results = e.result

    for connection, result in results.items():
        access_info = {
            'online': False,
            'accessible': False,
            'sudo': 'No'
        }
        nodes_context[connection.host]['access'] = access_info

        if isinstance(result, Exception):
            if NodeGroup.is_require_nopasswd_exception(result):
                # The error is thrown only if connection is successful, but something is wrong with sudo access.
                # In general, sudo password is incorrect. In our case, user is not a sudoer, or not a nopasswd sudoer.
                access_info['online'] = True
                access_info['accessible'] = True
            elif isinstance(result, socket.timeout):
                # Usually when node is off. All statuses are unchecked.
                pass
            elif isinstance(result, paramiko.ssh_exception.SSHException):
                # At least, node is on, but something is wrong with ssh credentials (user / identity key)
                access_info['online'] = True
            elif isinstance(result, paramiko.ssh_exception.NoValidConnectionsError):
                # Internal socket error, for example, when ssh daemon is off. All statuses are unchecked.
                pass
            else:
                raise exc
        else:
            access_info['online'] = True
            access_info['accessible'] = True
            access_info['sudo'] = "Yes"


def whoami(cluster: KubernetesCluster) -> NodeGroupResult:
    '''
    Determines different nodes access information, such as if the node is online, ssh credentials are correct, etc.
    '''
    _detect_nodes_access_info(cluster)

    results = cluster.nodes["all"].get_sudo_nodes().sudo("whoami")
    for connection, result in results.items():
        node_ctx = cluster.context['nodes'][connection.host]
        node_ctx['access']['sudo'] = 'Root' if result.stdout.strip() == "root" else 'Yes'
    return results


@restrict_empty_group
def get_nodes_time(group: NodeGroup) -> (float, Dict[fabric.connection.Connection, float], float):
    """
    Polls the time from the specified group of nodes, parses it and returns tuple with results.
    :param group: Group of nodes, where timestamps should be detected.
    :return: tuple with max timestamp, dict of parsed timestamps per node and max found time difference.

    Max time required for comparing dates computed on nodes, because we can not detect real time between nodes.
    Max nodes time should be less than minimal compared time from future.

    Timestamp - is a time in milliseconds since epoch.
    """

    # Please, note: this method can not detect time on nodes precisely, since Kubemarine can execute commands not at the
    # same time depending on various factors, for example, restrictions on the number of open sockets.

    parsed_time_per_node: Dict[fabric.connection.Connection, float] = {}

    min_time = None
    max_time = None

    # TODO: request and parse more accurate timestamp in milliseconds

    raw_results = group.run('date')
    for host, result in raw_results.items():
        parsed_time = parse(result.stdout.strip()).timestamp() * 1000
        parsed_time_per_node[host] = parsed_time
        if min_time is None or min_time > parsed_time:
            min_time = parsed_time
        if max_time is None or max_time < parsed_time:
            max_time = parsed_time

    return max_time, parsed_time_per_node, max_time-min_time
