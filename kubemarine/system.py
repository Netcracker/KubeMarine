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
from typing import Dict, Tuple, Optional, List

from dateutil.parser import parse
from ordered_set import OrderedSet

from kubemarine import selinux, kubernetes, apparmor, sysctl, modprobe
from kubemarine.core import utils, static
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RunnersResult, Token, GenericResult, Callback, RawExecutor
from kubemarine.core.group import (
    GenericGroupResult, RunnersGroupResult, GroupResultException,
    NodeGroup, DeferredGroup, AbstractGroup, GROUP_RUN_TYPE, CollectorCallback
)
from kubemarine.core.annotations import restrict_empty_group


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:

    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') \
        and (cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') or
             cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP')):
        raise Exception('chrony and timesyncd configured both at the same time')

    return inventory


def enrich_etc_hosts(inventory: dict, cluster: KubernetesCluster) -> dict:
# enrich only etc_hosts_generated object, etc_hosts remains as it is

    # if by chance cluster.yaml contains non empty etc_hosts_generated we have to reset it
    inventory['services']['etc_hosts_generated'] = {}

    control_plain = inventory['control_plain']['internal']

    control_plain_names = []
    control_plain_names.append(cluster.inventory['cluster_name'])
    control_plain_names.append('control-plain')
    control_plain_names = list(OrderedSet(control_plain_names))
    inventory['services']['etc_hosts_generated'][control_plain] = control_plain_names

    for node in cluster.inventory['nodes']:
        if 'remove_node' in node['roles']:
            continue

        internal_node_ip_names: List[str] = inventory['services']['etc_hosts_generated'].get(node['internal_address'], [])

        internal_node_ip_names.append("%s.%s" % (node['name'], cluster.inventory['cluster_name']))
        internal_node_ip_names.append(node['name'])
        internal_node_ip_names = list(OrderedSet(internal_node_ip_names))
        inventory['services']['etc_hosts_generated'][node['internal_address']] = internal_node_ip_names

        if node.get('address'):
            external_node_ip_names: List[str] = inventory['services']['etc_hosts_generated'].get(node['address'], [])

            external_node_ip_names.append("%s-external.%s" % (node['name'], cluster.inventory['cluster_name']))
            external_node_ip_names.append(node['name'] + "-external")
            external_node_ip_names = list(OrderedSet(external_node_ip_names))
            inventory['services']['etc_hosts_generated'][node['address']] = external_node_ip_names

    return inventory


def enrich_kernel_modules(inventory: dict, cluster: KubernetesCluster) -> dict:
    """
    The method enrich the list of kernel modules ('services.modprobe') according to OS family
    """

    final_nodes = cluster.nodes['all'].get_final_nodes()
    for os_family in ('debian', 'rhel', 'rhel8', 'rhel9'):
        # Remove the section for OS families if no node has these OS families.
        if final_nodes.get_subgroup_with_os(os_family).is_empty():
            del inventory["services"]["modprobe"][os_family]

    return inventory


def fetch_os_versions(cluster: KubernetesCluster) -> RunnersGroupResult:
    group = cluster.nodes['all'].get_accessible_nodes()
    '''
    For Red Hat, CentOS, Oracle Linux, and Ubuntu information in /etc/os-release /etc/redhat-release is sufficient but,
    Debian stores the full version in a special file. sed transforms version string, eg 10.10 becomes DEBIAN_VERSION="10.10"  
    '''

    return group.run(
        "cat /etc/*elease; cat /etc/debian_version 2> /dev/null | sed 's/\\(.\\+\\)/DEBIAN_VERSION=\"\\1\"/' || true")


def detect_os_family(cluster: KubernetesCluster) -> None:
    results = fetch_os_versions(cluster)

    for host, result in results.items():
        stdout = result.stdout.lower()

        version = None
        lines = ''

        version_regex = re.compile("\\s\\d*\\.\\d*", re.M)
        for line in stdout.split("\n"):
            if 'centos' in line or 'rhel' in line or 'rocky' in line:
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

        os_family = detect_os_family_by_name_version(name, version)

        cluster.log.debug("OS family: %s" % os_family)

        cluster.context["nodes"][host]["os"] = {
            'name': name,
            'version': version,
            'family': os_family
        }


def detect_os_family_by_name_version(name: str, version: str) -> str:
    os_family = 'unsupported'
    if name in static.GLOBALS["compatibility_map"]["distributives"]:
        os_family = 'unknown'
        os_family_list = static.GLOBALS["compatibility_map"]["distributives"][name]
        for os_family_item in os_family_list:
            if version in os_family_item["versions"]:
                os_family = os_family_item["os_family"]
                break

    return os_family


def update_resolv_conf(group: NodeGroup, config: dict) -> None:
    # TODO: Use Jinja template
    buffer = get_resolv_conf_buffer(config)
    utils.dump_file(group.cluster, buffer, 'resolv.conf')
    group.put(buffer, "/etc/resolv.conf", backup=True, immutable=True, sudo=True)


def get_resolv_conf_buffer(config: dict) -> io.StringIO:
    buffer = io.StringIO()
    if config.get("search") is not None:
        buffer.write("search %s\n" % config["search"])
    if config.get("nameservers") is not None:
        for address in config["nameservers"]:
            buffer.write("nameserver %s\n" % address)
    return buffer


def generate_etc_hosts_config(inventory: dict, etc_hosts_part: str = 'etc_hosts_generated') -> str:
# generate records for /etc/hosts from services.etc_hosts or services.etc_hosts_generated

    result = ""

    max_len_ip = 0

    for ip in list(inventory['services'][etc_hosts_part].keys()):
        if len(ip) > max_len_ip:
            max_len_ip = len(ip)

    for ip, names in inventory['services'][etc_hosts_part].items():
        if isinstance(names, list):
            # remove records with empty values from list
            names = list(filter(len, names))
            # if list is empty, then skip
            if not names:
                continue
            names = " ".join(names)
        result += "%s%s  %s\n" % (ip, " " * (max_len_ip - len(ip)), names)

    return result


def update_etc_hosts(group: NodeGroup, config: str) -> None:
    utils.dump_file(group.cluster, config, 'etc_hosts')
    group.put(io.StringIO(config), "/etc/hosts", backup=True, sudo=True)


def service_status(group: AbstractGroup[GROUP_RUN_TYPE], name: str, callback: Callback = None) -> GROUP_RUN_TYPE:
    return group.sudo('systemctl status %s' % name, warn=True, callback=callback)


def stop_service(group: AbstractGroup[GROUP_RUN_TYPE], name: str, callback: Callback = None) -> GROUP_RUN_TYPE:
    return group.sudo('systemctl stop %s' % name, callback=callback)


def start_service(group: AbstractGroup[GROUP_RUN_TYPE], name: str, callback: Callback = None) -> GROUP_RUN_TYPE:
    return group.sudo('systemctl start %s' % name, callback=callback)


def restart_service(group: AbstractGroup[GROUP_RUN_TYPE], name: str = None,
                    callback: Callback = None) -> GROUP_RUN_TYPE:
    if name is None:
        raise Exception("Service name can't be empty")
    return group.sudo('systemctl restart %s' % name, callback=callback)


def enable_service(group: AbstractGroup[GROUP_RUN_TYPE], name: str = None,
                   now: bool = True, callback: Callback = None) -> GROUP_RUN_TYPE:
    if name is None:
        raise Exception("Service name can't be empty")

    cmd = 'systemctl enable %s' % name
    if now:
        cmd = cmd + " --now"
    return group.sudo(cmd, callback=callback)


def disable_service(group: AbstractGroup[GROUP_RUN_TYPE], name: str = None,
                    now: bool = True, callback: Callback = None) -> GROUP_RUN_TYPE:
    if name is None:
        raise Exception("Service name can't be empty")

    cmd = 'systemctl disable %s' % name
    if now:
        cmd = cmd + " --now"
    return group.sudo(cmd, callback=callback)


def patch_systemd_service(group: DeferredGroup, service_name: str, patch_source: str) -> None:
    group.sudo(f"mkdir -p /etc/systemd/system/{service_name}.service.d")
    group.put(io.StringIO(utils.read_internal(patch_source)),
              f"/etc/systemd/system/{service_name}.service.d/{service_name}.conf",
              sudo=True)
    group.sudo("systemctl daemon-reload")


def fetch_firewalld_status(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo("systemctl status firewalld", warn=True)


def is_firewalld_disabled(group: NodeGroup) -> Tuple[bool, RunnersGroupResult]:
    result = fetch_firewalld_status(group)
    disabled_status = True

    for node_result in list(result.values()):
        if node_result.return_code != 4 and "disabled" not in node_result.stdout:
            disabled_status = False

    return disabled_status, result


def disable_firewalld(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    already_disabled, result = is_firewalld_disabled(group)

    if already_disabled:
        log.debug("Skipped - FirewallD already disabled or not installed")
        return result

    log.verbose("Trying to stop and disable FirewallD...")

    result = disable_service(group, name='firewalld', now=True)

    cluster.schedule_cumulative_point(reboot_nodes)
    cluster.schedule_cumulative_point(verify_system)

    return result


def is_swap_disabled(group: NodeGroup) -> Tuple[bool, RunnersGroupResult]:
    result = group.sudo("cat /proc/swaps", warn=True)
    disabled_status = True

    for node_result in list(result.values()):
        # is there any other lines excluding first head line?
        if node_result.stdout.strip().split('\n')[1:]:
            disabled_status = False

    return disabled_status, result


def disable_swap(group: NodeGroup) -> Optional[RunnersGroupResult]:
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

    return None


def reboot_nodes(cluster: KubernetesCluster) -> None:
    cluster.nodes["all"].get_new_nodes_or_self().call(reboot_group)


def reboot_group(group: NodeGroup, try_graceful: bool = None) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    if try_graceful is None:
        if 'controlplain_uri' not in cluster.context.keys():
            kubernetes.is_cluster_installed(cluster)

    graceful_reboot = try_graceful is True or \
                      (try_graceful is None and cluster.context['controlplain_uri'] is not None)

    if not graceful_reboot:
        return perform_group_reboot(group)

    log.verbose('Graceful reboot required')

    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    results: Dict[str, RunnersResult] = {}

    for node in group.get_ordered_members_list():
        node_config = node.get_config()
        node_name = node.get_node_name()
        cordon_required = 'control-plane' in node_config['roles'] or 'worker' in node_config['roles']
        if cordon_required:
            res = first_control_plane.sudo(
                kubernetes.prepare_drain_command(cluster, node_name, disable_eviction=False),
                warn=True)
            log.verbose(res)
        log.debug(f'Rebooting node "{node_name}"')
        raw_results = perform_group_reboot(node)
        if cordon_required:
            res = first_control_plane.sudo(f'kubectl uncordon {node_name}', warn=True)
            log.verbose(res)
        results.update(raw_results)

    return RunnersGroupResult(cluster, results)


def get_reboot_history(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('last reboot')


def perform_group_reboot(group: NodeGroup) -> RunnersGroupResult:
    log = group.cluster.log

    initial_boot_history = get_reboot_history(group)
    result = group.sudo(group.cluster.globals['nodes']['boot']['reboot_command'], warn=True)
    log.debug("Waiting for boot up...")
    log.verbose("Initial boot history:\n%s" % initial_boot_history)
    group.wait_for_reboot(initial_boot_history)
    return result


def reload_systemctl(group: AbstractGroup[GROUP_RUN_TYPE]) -> GROUP_RUN_TYPE:
    return group.sudo('systemctl daemon-reload')


def configure_chronyd(group: NodeGroup, retries: int = 60) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
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

            _, _, time_diff = get_nodes_time(group)
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


def configure_timesyncd(group: NodeGroup, retries: int = 120) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
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

            _, _, time_diff = get_nodes_time(group)
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


def verify_system(cluster: KubernetesCluster) -> None:
    group = cluster.nodes["all"].get_new_nodes_or_self()
    log = cluster.log
    # this method handles clusters with multiple OS
    os_family = group.get_nodes_os()

    if os_family in ['rhel', 'rhel8', 'rhel9'] and cluster.is_task_completed('prepare.system.setup_selinux'):
        log.debug("Verifying Selinux...")
        selinux_configured, selinux_result, selinux_parsed_result = \
            selinux.is_config_valid(group,
                                    state=selinux.get_expected_state(cluster.inventory),
                                    policy=selinux.get_expected_policy(cluster.inventory),
                                    permissive=selinux.get_expected_permissive(cluster.inventory))
        log.debug(selinux_result)
        if not selinux_configured:
            raise Exception("Selinux is still not configured")
    else:
        log.debug('Selinux verification skipped - origin task was not completed')

    if cluster.is_task_completed('prepare.system.setup_apparmor') and os_family == 'debian':
        log.debug("Verifying Apparmor...")
        expected_profiles = cluster.inventory['services']['kernel_security'].get('apparmor', {})
        apparmor_configured = apparmor.is_state_valid(group, expected_profiles)
        if not apparmor_configured:
            raise Exception("Apparmor is still not configured")
    else:
        log.debug('Apparmor verification skipped - origin task was not completed')

    if cluster.is_task_completed('prepare.system.disable_firewalld'):
        log.debug("Verifying FirewallD...")
        firewalld_disabled, firewalld_result = is_firewalld_disabled(group)
        log.debug(firewalld_result)
        if not firewalld_disabled:
            raise Exception("FirewallD is still enabled")
    else:
        log.debug('FirewallD verification skipped - origin disable task was not completed')

    if cluster.is_task_completed('prepare.system.disable_swap'):
        log.debug("Verifying swap...")
        swap_disabled, swap_result = is_swap_disabled(group)
        log.debug(swap_result)
        if not swap_disabled:
            raise Exception("Swap is still enabled")
    else:
        log.debug('Swap verification skipped - origin disable task was not completed')

    if cluster.is_task_completed('prepare.system.modprobe'):
        log.debug("Verifying modprobe...")
        modprobe_valid, _, modprobe_result = modprobe.is_modprobe_valid(group)
        log.debug(modprobe_result)
        if not modprobe_valid:
            raise Exception("Required kernel modules are not presented")
    else:
        log.debug('Modprobe verification skipped - origin setup task was not completed')

    if cluster.is_task_completed('prepare.system.sysctl'):
        log.debug("Verifying kernel parameters...")
        sysctl_valid = sysctl.is_valid(group)
        if not sysctl_valid:
            raise Exception("Required kernel parameters are not presented")
        else:
            log.debug("Required kernel parameters are presented")
    else:
        log.debug('Kernel parameters verification skipped - origin setup task was not completed')


def detect_active_interface(cluster: KubernetesCluster) -> None:
    group = cluster.nodes['all'].get_accessible_nodes()
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            detect_interface_by_address(node, node.get_config()['internal_address'], collector=collector)
    for host, result in collector.result.items():
        interface = result.stdout.strip()
        cluster.context['nodes'][host]['active_interface'] = interface


def detect_interface_by_address(group: DeferredGroup, address: str, collector: CollectorCallback) -> Token:
    return group.run("/usr/sbin/ip -o a | grep %s | awk '{print $2}'" % address, callback=collector)


def _detect_nodes_access_info(cluster: KubernetesCluster) -> None:
    nodes_context = cluster.context['nodes']
    hosts_unknown_status = [host for host, node_context in nodes_context.items() if 'access' not in node_context]
    group_unknown_status = cluster.make_group(hosts_unknown_status)
    if group_unknown_status.is_empty():
        return

    check_active_timeout = int(cluster.globals["nodes"]["remove"]["check_active_timeout"])
    exc = None
    results: GenericGroupResult[GenericResult]
    try:
        # This should invoke sudo last reboot
        results = group_unknown_status.wait_and_get_boot_history(timeout=check_active_timeout)
    except GroupResultException as e:
        exc = e
        results = e.result

    for host, result in results.items():
        access_info = {
            'online': False,
            'accessible': False,
            'sudo': 'No'
        }
        nodes_context[host]['access'] = access_info

        if isinstance(result, Exception):
            if RawExecutor.is_require_nopasswd_exception(result):
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
            elif isinstance(exc, Exception):
                raise exc
        else:
            access_info['online'] = True
            access_info['accessible'] = True
            access_info['sudo'] = "Yes"


def whoami(cluster: KubernetesCluster) -> RunnersGroupResult:
    '''
    Determines different nodes access information, such as if the node is online, ssh credentials are correct, etc.
    '''
    _detect_nodes_access_info(cluster)

    results = cluster.nodes["all"].get_sudo_nodes().sudo("whoami")
    for host, result in results.items():
        node_ctx = cluster.context['nodes'][host]
        node_ctx['access']['sudo'] = 'Root' if result.stdout.strip() == "root" else 'Yes'
    return results


@restrict_empty_group
def get_nodes_time(group: NodeGroup) -> Tuple[float, Dict[str, float], float]:
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

    parsed_time_per_node: Dict[str, float] = {}

    # TODO: request and parse more accurate timestamp in milliseconds

    raw_results = group.run('date')
    for host, result in raw_results.items():
        parsed_time = parse(result.stdout.strip()).timestamp() * 1000
        parsed_time_per_node[host] = parsed_time

    min_time = min(parsed_time_per_node.values())
    max_time = max(parsed_time_per_node.values())

    return max_time, parsed_time_per_node, max_time-min_time
