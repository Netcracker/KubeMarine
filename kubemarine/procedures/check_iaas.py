#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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


import argparse
import ipaddress
import math
import sys
from collections import OrderedDict
import time

import fabric

from kubemarine.core import flow
from kubemarine import system
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
                              hint="Failed to connect from deploy node to the remote node of the cluster. Check that "
                                   "the inventory is filled in correctly (key, username, nodes addresses), verify "
                                   "access to remote nodes.")


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
                                   "Check your network settings and status. It is necessary to reduce latency to %sms."
                                   % cluster.globals['compatibility_map']['network']['connection']['latency']['single']['critical'])
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['single']['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="Detected latency is higher than recommended value (%sms). Check your network settings "
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
                                   "Check your network settings and status. It is necessary to reduce latency to %sms."
                                   % cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['critical'])
        if average_latency > cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="Detected latency is higher than recommended value (%sms). Check your network settings "
                                "and status." % cluster.globals['compatibility_map']['network']['connection']['latency']['multi']['recommended'])
        tc.success(results="%sms" % average_latency)


def connection_sudoer_access(cluster):
    with TestCase(cluster.context['testsuite'], '004', 'SSH', 'Sudoer Access', default_results='Access provided'):
        non_root = []
        results = cluster.nodes['all'].sudo("whoami")
        cluster.log.verbose(results)
        for connection, result in results.items():
            if result.stdout.strip() != 'root':
                non_root.append(connection.host)
        if non_root:
            raise TestFailure("Non-sudoer access found at: %s" % ", ".join(non_root),
                              hint="Certain nodes do not have the appropriate sudoer access. At this nodes add "
                                   "connection user to sudoers group.")


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
                              hint="Increase the number of resources, so the number of %ss in the cluster should not "
                                   "be less than %s" % (beauty_name, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount']))

        if amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['amount']:
            beauty_name = group_name
            if group_name == 'all':
                beauty_name = 'all node'
            raise TestWarn("Less than recommended. Detected %s item%s" % (amount, s),
                           hint="Increase the number of resources, so the number of %ss in the cluster should not "
                                "be less than %s" % (beauty_name, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['amount']))

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
                           hint="Increase the number of RAM in the node configuration up to %sGB."
                                % cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram'])
        tc.success(results='%sGB' % minimal_amount)


def system_distributive(cluster):
    with TestCase(cluster.context['testsuite'], '008', 'System', 'Distibutive') as tc:
        supported_distributives = cluster.globals['compatibility_map']['distributives'].keys()

        cluster.log.debug(system.detect_os_family(cluster, suppress_exceptions=True))

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


def pod_subnet_connectivity(cluster):
    with TestCase(cluster.context['testsuite'], '009', 'Network', 'PodSubnet', default_results='Connected'):
        pod_subnet = cluster.inventory['services']['kubeadm']['networking']['podSubnet']
        failed_nodes = check_subnet_connectivity(cluster, pod_subnet)

        if failed_nodes:
            raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                              hint=f"Traffic is not allowed for pod subnet({pod_subnet}) on nodes: {failed_nodes}.")


def service_subnet_connectivity(cluster):
    with TestCase(cluster.context['testsuite'], '010', 'Network', 'ServiceSubnet', default_results='Connected'):
        service_subnet = cluster.inventory['services']['kubeadm']['networking']['serviceSubnet']
        failed_nodes = check_subnet_connectivity(cluster, service_subnet)

        if failed_nodes:
            raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                              hint=f"Traffic is not allowed for service subnet({service_subnet}) on nodes: {failed_nodes}.")


def cmd_for_ports(ports, query):
    result = ""
    for port in ports:
        result += f" && echo 'port: {port}' && ( {query % port} ) "
    return result[3:]


def tcp_connect(log, node_from, node_to, tcp_ports, host_to_ip, mtu):
    # 40 bites for headers
    mtu -= 40
    log.verbose(f"Trying connection from '{node_from['name']}' to '{node_to['name']}")
    cmd = cmd_for_ports(tcp_ports, f"echo $(dd if=/dev/urandom bs={mtu}  count=1) >/dev/tcp/{host_to_ip[node_to['name']]}/%s")
    node_from['connection'].sudo(cmd)


def get_start_socat_cmd():
    return "sudo nohup socat TCP-LISTEN:%s,reuseaddr,fork - &> /dev/null &"


def get_stop_socat_cmd():
    return "port=%s;pid=$(ps aux | grep ' socat ' | grep $port | grep -v grep | awk '{print $2}') " \
           "&& if [ ! -z $pid ]; then sudo kill -9 $pid; echo \"killed pid $pid for port $port\"; fi"


def check_tcp_connect_between_all_nodes(cluster, node_list, tcp_ports, host_to_ip):
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
                tcp_connect(cluster.log, node_list[j], node_list[i], tcp_ports, host_to_ip, mtu)
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
                tcp_connect(cluster.log, success_node, node, tcp_ports, host_to_ip, mtu)
                failed_nodes.remove(node["name"])
            except Exception as e:
                cluster.log.error(f"Subnet connectivity test failed from '{success_node['name']}' to '{node['name']}'")
                cluster.log.verbose(f"Exception details: {e}")

    return failed_nodes


def check_subnet_connectivity(cluster, subnet):
    inet = ipaddress.ip_network(subnet)
    net_mask = str(inet.netmask)
    subnet_hosts = list(inet.hosts())
    subnet_hosts_len = len(subnet_hosts)

    iface_cmd = "sudo ip -o a | grep %s | awk '{print $2}'"
    tcp_ports = ["30050"]
    node_list = cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True)
    host_to_ip = {}

    # Create alias from node network interface for subnet on every node
    # And run process that LISTEN TCP port
    i = 30
    for node in node_list:
        random_host = subnet_hosts[subnet_hosts_len - i]
        host_to_ip[node['name']] = random_host
        iface = iface_cmd % node['internal_address']
        socat_cmd = cmd_for_ports(tcp_ports, get_start_socat_cmd())
        node['connection'].sudo(f"ip a add {random_host}/{net_mask} dev $({iface}); " + socat_cmd)
        i = i + 1

    failed_nodes = check_tcp_connect_between_all_nodes(cluster, node_list, tcp_ports, host_to_ip)

    i = 30
    # Remove created aliases form network interfaces and kill created during test processes
    for node in node_list:
        random_host = subnet_hosts[subnet_hosts_len - i]
        iface = iface_cmd % node['internal_address']
        socat_cmd = cmd_for_ports(tcp_ports, get_stop_socat_cmd())
        node['connection'].sudo(socat_cmd + f" && ip a del {random_host}/{net_mask} dev $({iface})", warn=True)
        i = i + 1

    return failed_nodes


def check_tcp_ports(cluster):
    with TestCase(cluster.context['testsuite'], '011', 'Network', 'TCPPorts', default_results='Connected'):
        tcp_ports = ["80", "443", "6443", "2379", "2380", "10250", "10251", "10252", "30001", "30002"]
        node_list = cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True)
        host_to_ip = {}

        # Run process that LISTEN TCP port
        for node in node_list:
            host_to_ip[node['name']] = node['internal_address']
            socat_cmd = cmd_for_ports(tcp_ports, get_start_socat_cmd())
            res = node['connection'].sudo(socat_cmd)
            cluster.log.verbose(res)

        failed_nodes = check_tcp_connect_between_all_nodes(cluster, node_list, tcp_ports, host_to_ip)

        # Kill created during test processes
        for node in node_list:
            socat_cmd = cmd_for_ports(tcp_ports, get_stop_socat_cmd())
            node['connection'].sudo(socat_cmd)

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
            'masters': lambda cluster: hardware_members_amount(cluster, 'master'),
            'workers': lambda cluster: hardware_members_amount(cluster, 'worker'),
            'total': lambda cluster: hardware_members_amount(cluster, 'all'),
        },
        'cpu': {
            'balancers': lambda cluster: hardware_cpu(cluster, 'balancer'),
            'masters': lambda cluster: hardware_cpu(cluster, 'master'),
            'workers': lambda cluster: hardware_cpu(cluster, 'worker')
        },
        'ram': {
            'balancers': lambda cluster: hardware_ram(cluster, 'balancer'),
            'masters': lambda cluster: hardware_ram(cluster, 'master'),
            'workers': lambda cluster: hardware_ram(cluster, 'worker')
        }
    },
    'system': {
        'distributive': system_distributive
    }
})


def main(cli_arguments=None):
    parser = argparse.ArgumentParser(description='''
Script for checking Kubernetes cluster IAAS layer.

Hot to use:

''', formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='enable the verbosity mode')

    parser.add_argument('-c', '--config',
                        default='cluster.yaml',
                        help='define main cluster configuration file')

    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

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

    if cli_arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    context = flow.create_context(args, procedure='iaas',
                                  included_tasks=defined_tasks, excluded_tasks=defined_excludes)
    context['testsuite'] = TestSuite()

    cluster = flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        print_final_message=False
    )

    # Final summary should be printed only to stdout with custom formatting
    # If tests results required for parsing, they can be found in test results files
    print(cluster.context['testsuite'].get_final_summary())
    cluster.context['testsuite'].print_final_status(cluster.log)
    make_reports(cluster)
    return cluster.context['testsuite']


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
