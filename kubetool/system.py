import configparser
import io
import re
import time
from copy import deepcopy

import fabric
import yaml

from kubetool import selinux, kubernetes, packages
from kubetool.core import utils
from kubetool.core.cluster import KubernetesCluster
from kubetool.core.executor import RemoteExecutor
from kubetool.core.group import NodeGroupResult, NodeGroup
from kubetool.core.yaml_merger import default_merger


def verify_inventory(inventory, cluster):

    if cluster.inventory['services']['ntp'].get('chrony', {}).get('servers') \
        and (cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('NTP') or
             cluster.inventory['services']['ntp'].get('timesyncd', {}).get('Time', {}).get('FallbackNTP')):
        raise Exception('chrony and timesyncd configured both at the same time')

    # TODO: verify selinux and apparmor are not enabled at the same time

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


def detect_os_family(cluster, suppress_exceptions=False):
    group = cluster.nodes['all'].get_online_nodes()
    if cluster.context.get("initial_procedure") == "remove_node":
        # TODO: get rid of this construction
        active_timeout = int(cluster.globals["nodes"]["remove"]["check_active_timeout"])
        group = cluster.nodes['all'].wait_active_nodes(timeout=active_timeout)

    detected_os_family = None
    '''
    For Red Hat, CentOS, Oracle Linux, and Ubuntu information in /etc/os-release /etc/redhat-release is sufficient but,
    Debian stores the full version in a special file. sed transforms version string, eg 10.10 becomes DEBIAN_VERSION="10.10"  
    '''
    results = group.run("cat /etc/*elease; cat /etc/debian_version 2> /dev/null | sed 's/\\(.\\+\\)/DEBIAN_VERSION=\"\\1\"/' || true")

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

        group.cluster.context["nodes"][connection.host]["os"] = {
            'name': name,
            'version': version,
            'family': os_family
        }

    # todo: this is not good, we need to know if "old" nodes have different OS family
    #   maybe we should not use global static OS and use group-wise calculated OS?
    for node in group.get_new_nodes_or_self().get_ordered_members_list(provide_node_configs=True):
        os_family = group.cluster.context["nodes"][node['connect_to']]["os"]['family']
        if os_family == 'unknown' and not suppress_exceptions:
            raise Exception('OS family is unknown')
        if not detected_os_family:
            detected_os_family = os_family
        elif detected_os_family != os_family:
            detected_os_family = 'multiple'
            if not suppress_exceptions:
                raise Exception('OS families differ: detected %s and %s in same cluster' % (detected_os_family, os_family))

    group.cluster.context["os"] = detected_os_family

    return results


def get_os_family(cluster):
    if not is_os_detected(cluster):
        detect_os_family(cluster)
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

    # TODO: use jinja template
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


def is_os_detected(cluster):
    return bool(cluster.context.get("os"))


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


def is_firewalld_disabled(group):
    result = group.sudo("systemctl status firewalld", warn=True)
    disabled_status = True

    for node_result in list(result.values()):
        if node_result.return_code != 4 and "disabled" not in node_result.stdout:
            disabled_status = False

    return disabled_status, result


def disable_firewalld(group):
    log = group.cluster.log

    already_disabled, result = is_firewalld_disabled(group)

    if already_disabled:
        log.debug("Skipped - FirewallD already disabled or not installed")
        return result

    log.verbose("Trying to stop and disable FirewallD...")

    result = disable_service(group, name='firewalld', now=True)

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

    first_master = group.cluster.nodes['master'].get_first_member()
    results = NodeGroupResult()

    for node in group.get_ordered_members_list(provide_node_configs=True):
        cordon_required = cordone_on_graceful and ('master' in node['roles'] or 'worker' in node['roles'])
        if cordon_required:
            res = first_master.sudo(
                kubernetes.prepare_drain_command(node, group.cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                                 group.cluster.globals, False, group.cluster.nodes), warn=True)
            log.verbose(res)
        log.debug(f'Rebooting node "{node["name"]}"')
        raw_results = perform_group_reboot(node['connection'])
        if cordon_required:
            res = first_master.sudo(f'kubectl uncordon {node["name"]}', warn=True)
            log.verbose(res)
        results.update(raw_results)

    return results


def get_reboot_history(group: NodeGroup):
    return group.run('last reboot')


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
    # TODO: write to .bash_profile
    group.sudo("export PATH=$PATH:%s" % string)


def configure_chronyd(group, retries=60):
    log = group.cluster.log
    chronyd_config = ''

    for server in group.cluster.inventory['services']['ntp']['chrony']['servers']:
        chronyd_config += "server " + server + "\n"

    if group.cluster.inventory['services']['ntp']['chrony'].get('makestep'):
        chronyd_config += "\nmakestep " + group.cluster.inventory['services']['ntp']['chrony']['makestep']

    if group.cluster.inventory['services']['ntp']['chrony'].get('rtcsync', False):
        chronyd_config += "\nrtcsync"

    utils.dump_file(group.cluster, chronyd_config, 'chrony.conf')
    group.put(io.StringIO(chronyd_config), '/etc/chrony.conf', backup=True, sudo=True)
    group.sudo('systemctl restart chronyd')
    while retries > 0:
        log.debug("Waiting for time sync, retries left: %s" % retries)
        result = group.sudo('chronyc tracking && sudo chronyc sources')
        if "Normal" in list(result.values())[0].stdout:
            log.debug("Time synced!")
            return result
        else:
            log.debug("Time is not synced yet")
            log.debug(result)
        time.sleep(1)
        retries -= 1

    raise Exception("Time not synced, but timeout is reached")


def configure_timesyncd(group, retries=120):
    log = group.cluster.log
    timesyncd_config = ''

    for section, options in group.cluster.inventory['services']['ntp']['timesyncd'].items():
        timesyncd_config += '[%s]' % section
        for option_name, option_value in options.items():
            if isinstance(option_value, list):
                option_value_str = " ".join(option_value)
            else:
                option_value_str = str(option_value)
            timesyncd_config += '\n%s=%s' % (option_name, option_value_str)
        timesyncd_config += '\n\n'

    utils.dump_file(group.cluster, timesyncd_config, 'timesyncd.conf')
    group.put(io.StringIO(timesyncd_config), '/etc/systemd/timesyncd.conf', backup=True, sudo=True)
    res = group.sudo('timedatectl set-ntp true '
                     '&& sudo systemctl enable --now systemd-timesyncd.service '
                     '&& sudo systemctl restart systemd-timesyncd.service '
                     '&& sudo systemctl status systemd-timesyncd.service')
    log.verbose(res)
    while retries > 0:
        log.debug("Waiting for time sync, retries left: %s" % retries)
        result = group.sudo('timedatectl timesync-status && sudo timedatectl status')
        if "synchronized: yes" in list(result.values())[0].stdout:
            log.debug("Time synced!")
            return result
        else:
            log.debug("Time is not synced yet")
            log.debug(result)
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
                log.verbose('Kernel module %s not found at %s' % (module_name, conn.host))
                is_valid = False

    return is_valid, verify_results


def verify_system(group):
    log = group.cluster.log

    if group.cluster.is_task_completed('prepare.system.setup_selinux'):
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
        log.verbose('Selinux verification skipped - origin task was not completed')

    if group.cluster.is_task_completed('prepare.system.setup_apparmor'):
        log.debug("Verifying Apparmor...")
        # TODO
        # if not apparmor_configured:
        #     raise Exception("Selinux is still not configured")
    else:
        log.verbose('Apparmor verification skipped - origin task was not completed')

    if group.cluster.is_task_completed('prepare.system.disable_firewalld'):
        log.debug("Verifying FirewallD...")
        firewalld_disabled, firewalld_result = is_firewalld_disabled(group)
        log.debug(firewalld_result)
        if not firewalld_disabled:
            raise Exception("FirewallD is still enabled")
    else:
        log.verbose('FirewallD verification skipped - origin disable task was not completed')

    if group.cluster.is_task_completed('prepare.system.disable_swap'):
        log.debug("Verifying swap...")
        swap_disabled, swap_result = is_swap_disabled(group)
        log.debug(swap_result)
        if not swap_disabled:
            raise Exception("Swap is still enabled")
    else:
        log.verbose('Swap verification skipped - origin disable task was not completed')

    if group.cluster.is_task_completed('prepare.system.modprobe'):
        log.debug("Verifying modprobe...")
        modprobe_valid, swap_result = is_modprobe_valid(group)
        log.debug(swap_result)
        if not modprobe_valid:
            raise Exception("Required kernel modules are not presented")
    else:
        log.verbose('Modprobe verification skipped - origin setup task was not completed')


def detect_active_interface(group: NodeGroup):
    with RemoteExecutor(group.cluster.log) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            detect_interface_by_address(node['connection'], node['internal_address'])
    for host, host_results in exe.get_last_results().items():
        try:
            interface = list(host_results.values())[0].stdout.strip()
        except Exception:
            interface = None
        group.cluster.context['nodes'][host]['online'] = True
        group.cluster.context['nodes'][host]['active_interface'] = interface

    return exe.get_last_results_str()


def detect_interface_by_address(connection: fabric.connection.Connection, address: str):
    return connection.sudo("sudo ip -o a | grep %s | awk '{print $2}'" % address)


def whoami(group: NodeGroup) -> NodeGroupResult:
    '''
    Determines which nodes are enabled and which ones are disabled
    '''
    if group.cluster.context['initial_procedure'] == 'remove_node':
        online_nodes = group.wait_active_nodes()
    else:
        online_nodes = group
    offline_nodes = group.exclude_group(online_nodes)
    results = online_nodes.sudo("whoami")
    for connection, result in results.items():
        group.cluster.context['nodes'][connection.host]['online'] = True
        group.cluster.context['nodes'][connection.host]['hasroot'] = result.stdout.strip() == "root"
    if not offline_nodes.is_empty():
        for node in offline_nodes.get_ordered_members_list(provide_node_configs=True):
            group.cluster.context['nodes'][node['connect_to']]['online'] = False
            group.cluster.context['nodes'][node['connect_to']]['hasroot'] = False
    return results
