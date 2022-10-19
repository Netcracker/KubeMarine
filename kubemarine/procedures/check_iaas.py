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


import ipaddress
import math
import re
import sys
import uuid
from collections import OrderedDict
import time
from contextlib import contextmanager

import fabric

from kubemarine.core import flow, utils
from kubemarine import system
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.resources import DynamicResources
from kubemarine.testsuite import TestSuite, TestCase, TestFailure, TestWarn


def connection_ssh_connectivity(cluster):
    with TestCase(cluster.context['testsuite'], '001', 'SSH', 'Connectivity', default_results='Connected'):
        failed_nodes = []
        for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
            try:
                cluster.log.verbose(node['connection'].run("echo 1"))
            except fabric.group.GroupException as e:
                failed_nodes.append(node['name'])
                cluster.log.error("Connection test failed for node \"%s\"" % node['name'])
                cluster.log.error("Exception details:")
                cluster.log.error(e)
        if failed_nodes:
            raise TestFailure("Failed to connect to %s nodes" % len(failed_nodes),
                              hint="Failed to connect from the deploy node to the remote node of the cluster. Check that "
                                   "the inventory details (key, username, and nodes addresses) are entered correctly, and verify "
                                   "the access to remote nodes.")


def connection_ssh_latency_single(cluster):
    with TestCase(cluster.context['testsuite'], '002',  'SSH', 'Latency - Single Thread',
                  minimal=cluster.globals['compatibility_map']['network']['connection']['latency']['single']['critical'],
                  recommended=cluster.globals['compatibility_map']['network']['connection']['latency']['single']['recommended']) as tc:
        i = 0
        measurements = []
        while i < 5:
            i += 1
            for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
                time_start = time.time()
                node['connection'].run("echo 1")
                time_end = time.time()
                diff = (time_end - time_start) * 1000
                cluster.log.debug('Connection to %s - %sms' % (node['name'], diff))
                measurements.append(diff)
        average_latency = math.floor(sum(measurements) / cluster.nodes['all'].nodes_amount() / 5)
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['single']['critical']:
            raise TestFailure("Very high latency: %sms" % average_latency,
                              hint="A very high latency was detected between the deploy node and cluster nodes. "
                                   "Check your network settings and status. It is necessary to reduce the latency to %sms."
                                   % cluster.globals['compatibility_map']['network']['connection']['latency']['single']['critical'])
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['single']['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="The detected latency is higher than the recommended value (%sms). Check your network settings "
                                "and status." % cluster.globals['compatibility_map']['network']['connection']['latency']['single']['recommended'])
        tc.success(results="%sms" % average_latency)


def connection_ssh_latency_multiple(cluster):
    with TestCase(cluster.context['testsuite'], '003',  'SSH', 'Latency - Multi Thread',
                  minimal=cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['critical'],
                  recommended=cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['recommended']) as tc:
        i = 0
        measurements = []
        while i < 10:
            i += 1
            time_start = time.time()
            cluster.nodes['all'].run("echo 1")
            time_end = time.time()
            diff = (time_end - time_start) * 1000
            cluster.log.debug('Average latency at step %s - %sms' % (i, diff))
            measurements.append(diff)
        average_latency = math.floor(sum(measurements) / 10)
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['critical']:
            raise TestFailure("Very high latency: %sms" % average_latency,
                              hint="A very high latency was detected between the deploy node and cluster nodes. "
                                   "Check your network settings and status. It is necessary to reduce the latency to %sms."
                                   % cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['critical'])
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="The detected latency is higher than the recommended value (%sms). Check your network settings "
                                "and status." % cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['recommended'])
        tc.success(results="%sms" % average_latency)


def connection_sudoer_access(cluster):
    with TestCase(cluster.context['testsuite'], '004', 'SSH', 'Sudoer Access', default_results='Access provided'):
        non_root = []
        for host, node_context in cluster.context['nodes'].items():
            access_info = node_context['access']
            if access_info['online'] and access_info['sudo'] == 'Root':
                cluster.log.debug("%s online and has root" % host)
            else:
                non_root.append(host)
        if non_root:
            raise TestFailure("Non-sudoer access found at: %s" % ", ".join(non_root),
                              hint="Certain nodes do not have the appropriate sudoer access. At these nodes, add "
                                   "a connection user to the sudoers group.")


def hardware_members_amount(cluster, group_name):
    beauty_name = group_name.capitalize()
    if group_name == 'vip':
        beauty_name = 'VIP'
    if group_name == 'all':
        beauty_name = 'Total Node'

    with TestCase(cluster.context['testsuite'], '005',  'Hardware', '%ss Amount' % beauty_name,
                  minimal=cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount'],
                  recommended=cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['amount']) as tc:
        amount = 0
        if group_name == 'vip':
            amount = len(cluster.inventory.get('vrrp_ips', []))
        else:
            group = cluster.nodes.get(group_name)
            if group is not None:
                amount = group.nodes_amount()

        s = ''
        if amount != 1:
            s = 's'

        if amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount']:
            beauty_name = group_name
            if group_name == 'all':
                beauty_name = 'all node'
            raise TestFailure("Less than minimal. Detected %s item%s" % (amount, s),
                              hint="Increase the number of resources, so that the number of %ss in the cluster should not "
                                   "be less than %s." % (beauty_name, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount']))

        if amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['amount']:
            beauty_name = group_name
            if group_name == 'all':
                beauty_name = 'all node'
            raise TestWarn("Less than recommended. Detected %s item%s" % (amount, s),
                           hint="Increase the number of resources, so that the number of %ss in the cluster should not "
                                "be less than %s." % (beauty_name, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount']))

        tc.success("%s item%s" % (amount, s))


def hardware_cpu(cluster, group_name):
    with TestCase(cluster.context['testsuite'], '006',  'Hardware', 'VCPUs Amount - %ss' % group_name.capitalize(),
                  minimal=cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'],
                  recommended=cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']) as tc:
        if cluster.nodes.get(group_name) is None or cluster.nodes[group_name].is_empty():
            return tc.success(results='Skipped')
        results = cluster.nodes[group_name].sudo("nproc --all")
        cluster.log.verbose(results)
        minimal_amount = None
        for connection, result in results.items():
            amount = int(result.stdout)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu']:
                cluster.log.error('%s node %s has insufficient VCPUs: expected %s, but %s found.'
                                  % (group_name.capitalize(), connection.host, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'], amount))
            elif amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']:
                cluster.log.warning('%s node %s has less VCPUs than recommended: recommended %s, but %s found.'
                                    % (group_name.capitalize(), connection.host, cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu'], amount))
            else:
                cluster.log.debug('%s node %s has enough VCPUs: %s' % (group_name.capitalize(), connection.host, amount))

        s = ''
        if minimal_amount != 1:
            s = 's'

        if minimal_amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu']:
            raise TestFailure("Less than minimal. Detected %s VCPU%s" % (minimal_amount, s),
                              hint="Increase the number of VCPUs in the node configuration to at least the minimum "
                                   "value: %s VCPUs." % cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'])
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']:
            raise TestWarn("Less than recommended. Detected %s VCPU%s" % (minimal_amount, s),
                           hint="Increase the number of VCPUs in the node configuration up to %s VCPUs."
                                % cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu'])
        tc.success(results='%s VCPU%s' % (minimal_amount, s))


def hardware_ram(cluster, group_name):
    with TestCase(cluster.context['testsuite'], '007',  'Hardware', 'RAM Amount - %ss' % group_name.capitalize(),
                  minimal=cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'],
                  recommended=cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']) as tc:
        if cluster.nodes.get(group_name) is None or cluster.nodes[group_name].is_empty():
            return tc.success(results='Skipped')
        results = cluster.nodes[group_name].sudo("cat /proc/meminfo | awk '/DirectMap/ { print $2 }'")
        cluster.log.verbose(results)
        minimal_amount = None
        for connection, result in results.items():
            amount = math.floor(sum(map(lambda x: int(x), result.stdout.strip().split("\n"))) / 1000000)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram']:
                cluster.log.error('%s node %s has insufficient RAM: expected %sGB, but %sGB found.'
                                  % (group_name.capitalize(), connection.host, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'], amount))
            elif amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']:
                cluster.log.warning('%s node %s has less RAM than recommended: recommended %sGB, but %sGB found.'
                                    % (group_name.capitalize(), connection.host, cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram'], amount))
            else:
                cluster.log.debug('%s node %s has enough RAM: %sGB' % (group_name.capitalize(), connection.host, amount))
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram']:
            raise TestFailure("Less than minimal. Detected %sGB" % minimal_amount,
                              hint="Increase the number of RAM in the node configuration to at least the minimum "
                                   "value: %sGB." % cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'])
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']:
            raise TestWarn("Less than recommended. Detected %sGB" % minimal_amount,
                           hint="Increase the number of RAM in the node configuration up to %s GB."
                                % cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram'])
        tc.success(results='%sGB' % minimal_amount)


def system_distributive(cluster):
    with TestCase(cluster.context['testsuite'], '008', 'System', 'Distibutive') as tc:
        supported_distributives = cluster.globals['compatibility_map']['distributives'].keys()

        cluster.log.debug(system.fetch_os_versions(cluster))

        detected_unsupported_os = []
        detected_supported_os = []
        detected_unsupported_version = []
        supported_versions = []
        for address, context_data in cluster.context["nodes"].items():
            detected_os = '%s %s' % (context_data['os']['name'], context_data['os']['version'])
            if context_data['os']['family'] == 'unsupported': 
                detected_unsupported_os.append(detected_os)
                cluster.log.error('Host %s running unsupported OS \"%s\"' % (address, detected_os))
            elif context_data['os']['family'] == 'unknown':
                detected_unsupported_version.append(detected_os)
                os_family_list = cluster.globals["compatibility_map"]["distributives"][context_data['os']['name']]
                versions = []
                for os_family_item in os_family_list:
                    versions.extend(os_family_item["versions"])
                supported_versions.append('%s: %s' %(context_data['os']['name'], versions))
                cluster.log.error('Host %s running unknown OS family \"%s\"' % (address, detected_os))
            else:
                detected_supported_os.append(detected_os)
                cluster.log.debug('Host %s running \"%s\"' % (address, detected_os))

        detected_supported_os = list(set(detected_supported_os))
        detected_unsupported_os = list(set(detected_unsupported_os))
        detected_unsupported_version = list(set(detected_unsupported_version))
        supported_versions = list(set(supported_versions))

        if detected_unsupported_os:
            raise TestFailure("Unsupported OS: %s" % ", ".join(detected_unsupported_os),
                              hint="Reinstall the OS on the host to one of the supported: %s" % ", ".join(supported_distributives))

        if detected_unsupported_version:
            raise TestFailure("Unsupported version: %s" % ", ".join(detected_unsupported_version),
                              hint="Reinstall the OS on the host to one of the supported versions: %s" % \
                                      ", ".join(supported_versions))

        tc.success(results=", ".join(detected_supported_os))


def detect_preinstalled_python(cluster: KubernetesCluster):
    version_pattern = r'^Python{space}([2-3])(\.[0-9]+){{0,2}}$'
    bash_version_pattern = version_pattern.format(space='[[:space:]]')
    python_version_pattern = version_pattern.format(space=' ')
    nodes_context = cluster.context['nodes']
    hosts_unknown_python = [host for host, node_context in nodes_context.items() if 'python' not in node_context]
    group_unknown_python = cluster.make_group(hosts_unknown_python)
    detected_python = group_unknown_python.run(
        rf'for i in $(whereis -b python && whereis -b python3 ); do '
        rf'if [[ -f "$i" ]] && [[ $($i --version 2>&1 | head -n 1) =~ {bash_version_pattern} ]]; then '
        rf'echo "$i"; $i --version 2>&1; break; '
        rf'fi; done')

    for conn, result in detected_python.items():
        result = result.stdout.strip()
        if not result:
            raise TestFailure("Failed to detect preinstalled python executable. The task cannot be performed.")

        executable, version = tuple(result.splitlines())
        version = re.match(python_version_pattern, version).group(1)
        nodes_context[conn.host]["python"] = {
            "executable": executable,
            "major_version": version
        }


@contextmanager
def suspend_firewalld(cluster: KubernetesCluster):
    firewalld_statuses = system.fetch_firewalld_status(cluster.nodes["all"])
    stop_firewalld_group = firewalld_statuses.get_nodes_group_where_value_in_stdout("active (running)")

    nodes_to_rollback = cluster.make_group([])
    try:
        try:
            nodes_to_rollback = system.stop_service(stop_firewalld_group, "firewalld").get_group()
        except fabric.group.GroupException as e:
            nodes_to_rollback = e.result.get_exited_nodes_group()
            raise

        yield
    finally:
        system.start_service(nodes_to_rollback, "firewalld")


def _get_not_balancers(cluster: KubernetesCluster) -> dict:
    nodes = {}
    for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
        # exclude nodes which are only balancers.
        if node["roles"] == ["balancer"]:
            cluster.log.debug(f"Exclude balancer '{node['name']}' from subnet connectivity check.")
            continue
        nodes[node["connect_to"]] = node

    return nodes


@contextmanager
def assign_random_ips(cluster: KubernetesCluster, nodes: dict, subnet):
    inet = ipaddress.ip_network(subnet)
    net_mask = str(inet.netmask)
    prefix = str(inet.prefixlen)
    subnet_hosts = []
    ip_numbers=0
    for i in inet.hosts():
        subnet_hosts.append(i)
        ip_numbers +=1
        if ip_numbers == 1000000:
           break
    subnet_hosts_len = len(subnet_hosts)

    host_to_inf = {}
    host_to_ip = {}
    skipped_nodes = []
    nodes_to_rollback = cluster.make_group([])

    try:
        # Assign random IP for the subnet on every node
        i = 30
        for host, node in nodes.items():
            inf = cluster.context['nodes'][host]['active_interface']
            if not inf:
                raise TestFailure(f"Failed to detect active interface on {node['name']}")
            host_to_inf[host] = inf
            random_host = subnet_hosts[subnet_hosts_len - i]
            host_to_ip[host] = random_host
            i = i + 1

        with RemoteExecutor(cluster) as exe:
            for host, node in nodes.items():
                existing_alias = f"ip -o a | grep {host_to_inf[host]} | grep {host_to_ip[host]}"
                node['connection'].sudo(existing_alias, warn=True)

            exe.flush()
            for cxn, result in exe.get_merged_result().items():
                host = cxn.host
                if not result.stdout and not result.stderr and result.exited == 1:
                    # grep returned nothing, subnet is not used.
                    pass
                else:
                    skipped_nodes.append(nodes[host]["name"])
                    del nodes[host]

            # Create alias from the node network interface for the subnet on every node
            for host, node in nodes.items():
                node['connection'].sudo(f"ip a add {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}")

            exe.flush()
            try:
                nodes_to_rollback = exe.get_merged_result().get_group()
            except fabric.group.GroupException as e:
                nodes_to_rollback = e.result.get_exited_nodes_group()
                raise

        yield host_to_ip
    finally:
        # Remove the created aliases from network interfaces
        with RemoteExecutor(cluster):
            for node in nodes_to_rollback.get_ordered_members_list(provide_node_configs=True):
                host = node["connect_to"]
                node['connection'].sudo(f"ip a del {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}",
                                        warn=True)

    if skipped_nodes:
        raise TestWarn(f"Cannot perform check on {skipped_nodes}: subnet is already in use. "
                       f"Use check_paas procedure if you already have installed cluster.")


def pod_subnet_connectivity(cluster):
    with TestCase(cluster.context['testsuite'], '009', 'Network', 'PodSubnet', default_results='Connected'),\
            suspend_firewalld(cluster):
        pod_subnet = cluster.inventory['services']['kubeadm']['networking']['podSubnet']
        nodes = _get_not_balancers(cluster)
        tcp_ports = ["30050"]
        with assign_random_ips(cluster, nodes, pod_subnet) as host_to_ip, \
                install_tcp_listener(cluster, nodes, tcp_ports):
            failed_nodes = check_tcp_connect_between_all_nodes(cluster, list(nodes.values()), tcp_ports, host_to_ip)

            if failed_nodes:
                raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                                  hint=f"Traffic is not allowed for the pod subnet({pod_subnet}) "
                                       f"on nodes: {failed_nodes}.")


def service_subnet_connectivity(cluster):
    with TestCase(cluster.context['testsuite'], '010', 'Network', 'ServiceSubnet', default_results='Connected'),\
            suspend_firewalld(cluster):
        service_subnet = cluster.inventory['services']['kubeadm']['networking']['serviceSubnet']
        nodes = _get_not_balancers(cluster)
        tcp_ports = ["30050"]
        with assign_random_ips(cluster, nodes, service_subnet) as host_to_ip, \
                install_tcp_listener(cluster, nodes, tcp_ports):
            failed_nodes = check_tcp_connect_between_all_nodes(cluster, list(nodes.values()), tcp_ports, host_to_ip)

            if failed_nodes:
                raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                                  hint=f"Traffic is not allowed for the service subnet({service_subnet}) "
                                       f"on nodes: {failed_nodes}.")


def cmd_for_ports(ports, query):
    result = ""
    for port in ports:
        result += f" && echo 'port: {port}' && ( {query % port} ) "
    return result[3:]


def tcp_connect(cluster, node_from, node_to, tcp_ports, host_to_ip, mtu):
    # 40 bites for headers
    mtu -= 40
    cluster.log.verbose(f"Trying connection from '{node_from['name']}' to '{node_to['name']}")
    cmd = cmd_for_ports(tcp_ports, f"echo $(dd if=/dev/urandom bs={mtu}  count=1) >/dev/tcp/{host_to_ip[node_to['connect_to']]}/%s")
    node_from['connection'].sudo(cmd, timeout=cluster.globals['connection']['defaults']['timeout'])


def get_start_tcp_listener_cmd(python_executable, tcp_listener, ip_version):
    # 1. Create anonymous pipe
    # 2. Create python tcp listener process in background and redirect output to pipe
    # 3. Wait till the listener successfully binds the port, or till it fails and exits.
    #    Read one line from pipe to check that.
    # 4. Exit with success or fail correspondingly.
    return "PORT=%s; PIPE=$(mktemp -u); mkfifo $PIPE; exec 3<>$PIPE; rm $PIPE; " \
           f"sudo nohup {python_executable} {tcp_listener} $PORT {ip_version} >&3 2>&1 & " \
           "PID=$(echo $!); " \
           "while read -t 0.1 -u 3 || sudo kill -0 $PID 2>/dev/null && [[ -z $REPLY ]]; do " \
               ":; " \
           "done; " \
           "DATA=$REPLY; " \
           "if [[ $DATA == \"In use\" ]]; then " \
               "echo \"$PORT in use\" >&2 ; " \
               "exit 1; " \
           "elif [[ $DATA == \"Listen\" ]]; then " \
               "exit 0; " \
           "fi; " \
           "DATA=$(echo $DATA && dd iflag=nonblock status=none <&3 2>/dev/null); " \
           "echo \"$DATA\" >&2 ; " \
           "exit 1"


def get_stop_tcp_listener_cmd(tcp_listener):
    identify_pid = "ps aux | grep \" %s ${port} \" | grep -v grep | grep -v nohup | awk '{print $2}'" % tcp_listener
    return f"port=%s;pid=$({identify_pid}) " \
           "&& if [ ! -z $pid ]; then sudo kill -9 $pid; echo \"killed pid $pid for port $port\"; fi"


def check_tcp_connect_between_all_nodes(cluster, node_list, tcp_ports, host_to_ip):
    if len(node_list) <= 1:
        return []

    mtu = cluster.inventory['plugins']['calico']['mtu']

    cluster.log.verbose("Searching for success node...")
    success_node = None
    failed_nodes = []
    for node in node_list:
        failed_nodes.append(node['name'])
    nodes_for_check = []
    for node in node_list:
        nodes_for_check.append(node)

    for i in range(0, len(node_list)):
        for j in range(i + 1, len(node_list)):
            try:
                tcp_connect(cluster, node_list[j], node_list[i], tcp_ports, host_to_ip, mtu)
                # If node has at least one successful connection with another node - this node has appropriate settings.
                success_node = node_list[i]
                cluster.log.verbose(f"Successful node found: {success_node['name']}")
                failed_nodes.remove(success_node["name"])
                break
            except Exception as e:
                cluster.log.error(f"Subnet connectivity test failed from '{node_list[j]['name']}' to '{node_list[i]['name']}'")
                cluster.log.verbose(f"Exception details: {e}")

        nodes_for_check.remove(node_list[i])
        if success_node is not None:
            break

    # TCP connect from found successful node to every other node
    if success_node is not None:
        for node in nodes_for_check:
            try:
                tcp_connect(cluster, success_node, node, tcp_ports, host_to_ip, mtu)
                failed_nodes.remove(node["name"])
            except Exception as e:
                cluster.log.error(f"Subnet connectivity test failed from '{success_node['name']}' to '{node['name']}'")
                cluster.log.verbose(f"Exception details: {e}")

    return failed_nodes


@contextmanager
def install_tcp_listener(cluster: KubernetesCluster, nodes: dict, tcp_ports):
    detect_preinstalled_python(cluster)
    # currently tcp listener can be run on both python 2 and 3
    local_path = utils.get_resource_absolute_path('resources/scripts/simple_tcp_listener.py', script_relative=True)
    tcp_listener = "/tmp/%s.py" % uuid.uuid4().hex
    cluster.make_group(list(nodes.keys())).put(local_path, tcp_listener, binary=False)

    skipped_nodes = {}
    nodes_to_rollback = cluster.make_group([])
    try:
        with RemoteExecutor(cluster) as exe:
            # Run process that LISTEN TCP port
            for host, node in nodes.items():
                internal_ip = node.get('internal_address')
                ip_version = ipaddress.ip_address(internal_ip).version 
                python_executable = cluster.context['nodes'][host]['python']['executable']
                tcp_listener_cmd = cmd_for_ports(tcp_ports, get_start_tcp_listener_cmd(python_executable, tcp_listener, ip_version))
                node['connection'].sudo(tcp_listener_cmd, warn=True)

            exe.flush()
            try:
                results = exe.get_merged_result()
                nodes_to_rollback = results.get_group()
            except fabric.group.GroupException as e:
                nodes_to_rollback = e.result.get_exited_nodes_group()
                raise

            port_in_use = re.compile(r'^(\d+) in use$')
            for cxn, result in results.items():
                host = cxn.host
                matcher = port_in_use.match(result.stderr.strip())
                if matcher is not None:
                    skipped_nodes[nodes[host]["name"]] = matcher.group(1)
                    del nodes[host]
                elif result.exited != 0:
                    raise fabric.group.GroupException(results)
                else:
                    cluster.log.verbose(result)

        yield

    finally:
        with RemoteExecutor(cluster):
            # Kill the created during the test processes
            for node in nodes_to_rollback.get_ordered_members_list(provide_node_configs=True):
                tcp_listener_cmd = cmd_for_ports(tcp_ports, get_stop_tcp_listener_cmd(tcp_listener))
                node['connection'].sudo(tcp_listener_cmd, warn=True)

    if skipped_nodes:
        cluster.log.warning(f"Ports in use: {skipped_nodes}")
        raise TestWarn(f"Cannot perform check on {list(skipped_nodes.keys())}: some ports are already in use. "
                       f"Use check_paas procedure if you already have installed cluster.")


def check_tcp_ports(cluster):
    with TestCase(cluster.context['testsuite'], '011', 'Network', 'TCPPorts', default_results='Connected'),\
            suspend_firewalld(cluster):
        tcp_ports = ["80", "443", "6443", "2379", "2380", "10250", "10251", "10252", "30001", "30002"]
        nodes = {node["connect_to"]: node
                 for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True)}
        host_to_ip = {host: node['internal_address'] for host, node in nodes.items()}
        with install_tcp_listener(cluster, nodes, tcp_ports):
            failed_nodes = check_tcp_connect_between_all_nodes(cluster, list(nodes.values()), tcp_ports, host_to_ip)

            if failed_nodes:
                raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                                  hint=f"Not all needed tcp ports are opened on nodes: {failed_nodes}. "
                                       f"Ports that should be opened: {tcp_ports}")


def make_reports(cluster):
    if not cluster.context['execution_arguments'].get('disable_csv_report', False):
        cluster.context['testsuite'].save_csv(cluster.context['execution_arguments']['csv_report'], cluster.context['execution_arguments']['csv_report_delimiter'])
    if not cluster.context['execution_arguments'].get('disable_html_report', False):
        cluster.context['testsuite'].save_html(cluster.context['execution_arguments']['html_report'], cluster.context['initial_procedure'].upper())


tasks = OrderedDict({
    'ssh': {
        # todo this is useless, because flow.load_inventory already fails in case of no connectivity
        'connectivity': connection_ssh_connectivity,
        'latency': {
            'single': connection_ssh_latency_single,
            'multiple': connection_ssh_latency_multiple
        },
        'sudoer_access': connection_sudoer_access,
    },
    'network': {
        'pod_subnet_connectivity': pod_subnet_connectivity,
        'service_subnet_connectivity': service_subnet_connectivity,
        'check_tcp_ports': check_tcp_ports
    },
    'hardware': {
        'members_amount': {
            'vips': lambda cluster: hardware_members_amount(cluster, 'vip'),
            'balancers': lambda cluster: hardware_members_amount(cluster, 'balancer'),
            'control-planes': lambda cluster: hardware_members_amount(cluster, 'control-plane'),
            'workers': lambda cluster: hardware_members_amount(cluster, 'worker'),
            'total': lambda cluster: hardware_members_amount(cluster, 'all'),
        },
        'cpu': {
            'balancers': lambda cluster: hardware_cpu(cluster, 'balancer'),
            'control-planes': lambda cluster: hardware_cpu(cluster, 'control-plane'),
            'workers': lambda cluster: hardware_cpu(cluster, 'worker')
        },
        'ram': {
            'balancers': lambda cluster: hardware_ram(cluster, 'balancer'),
            'control-planes': lambda cluster: hardware_ram(cluster, 'control-plane'),
            'workers': lambda cluster: hardware_ram(cluster, 'worker')
        }
    },
    'system': {
        'distributive': system_distributive
    }
})


class IaasAction(Action):
    def __init__(self):
        super().__init__('check iaas')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for checking Kubernetes cluster IAAS layer.
    
    Hot to use:

    '''

    parser = flow.new_tasks_flow_parser(cli_help)

    parser.add_argument('--csv-report',
                        default='report.csv',
                        help='define CSV report file location')

    parser.add_argument('--csv-report-delimiter',
                        default=';',
                        help='define delimiter type for CSV report')

    parser.add_argument('--html-report',
                        default='report.html',
                        help='define HTML report file location')

    parser.add_argument('--disable-csv-report',
                        action='store_true',
                        help='forcibly disable CSV report file creation')

    parser.add_argument('--disable-html-report',
                        action='store_true',
                        help='forcibly disable HTML report file creation')

    context = flow.create_context(parser, cli_arguments, procedure='iaas')
    context['testsuite'] = TestSuite()
    context['preserve_inventory'] = False

    cluster = flow.run_actions(context, [IaasAction()], print_final_message=False)

    # Final summary should be printed only to stdout with custom formatting
    # If test results are required for parsing, they can be found in the test results files
    print(cluster.context['testsuite'].get_final_summary())
    cluster.context['testsuite'].print_final_status(cluster.log)
    make_reports(cluster)
    return cluster.context['testsuite']


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
