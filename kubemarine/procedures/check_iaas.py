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
import io
import ipaddress
import math
import os
import random
import re
import sys
import uuid
from collections import OrderedDict
import time
from contextlib import contextmanager, nullcontext, AbstractContextManager
from typing import List, Dict, cast, Match, Iterator, Optional, Tuple, Set, Union

import yaml
from ordered_set import OrderedSet

from kubemarine.core import flow, utils, static
from kubemarine import system, packages, jinja
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.testsuite import TestSuite, TestCase, TestFailure, TestWarn
from kubemarine.core.group import (
    NodeConfig, NodeGroup, DeferredGroup, GroupException, GroupResultException, CollectorCallback
)

_CONNECTIVITY_PORTS: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]] = {}


def connection_ssh_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '001', 'SSH', 'Connectivity', default_results='Connected'):
        failed_nodes = []
        for node in cluster.nodes['all'].get_ordered_members_list():
            try:
                cluster.log.verbose(node.run("echo 1"))
            except GroupException as e:
                failed_nodes.append(node.get_node_name())
                cluster.log.error("Connection test failed for node \"%s\"" % node.get_node_name())
                cluster.log.error("Exception details:")
                cluster.log.error(e)
        if failed_nodes:
            raise TestFailure("Failed to connect to %s nodes" % len(failed_nodes),
                              hint="Failed to connect from the deploy node to the remote node of the cluster. Check that "
                                   "the inventory details (key, username, and nodes addresses) are entered correctly, and verify "
                                   "the access to remote nodes.")


def connection_ssh_latency_single(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '002',  'SSH', 'Latency - Single Thread',
                  minimal=cluster.globals['compatibility_map']['network']['connection']['latency']['single']['critical'],
                  recommended=cluster.globals['compatibility_map']['network']['connection']['latency']['single']['recommended']) as tc:
        i = 0
        measurements = []
        while i < 5:
            i += 1
            for node in cluster.nodes['all'].get_ordered_members_list():
                time_start = time.time()
                node.run("echo 1")
                time_end = time.time()
                diff = (time_end - time_start) * 1000
                cluster.log.debug('Connection to %s - %sms' % (node.get_node_name(), diff))
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


def connection_ssh_latency_multiple(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '003',  'SSH', 'Latency - Multi Thread',
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


def connection_sudoer_access(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '004', 'SSH', 'Sudoer Access', default_results='Access provided'):
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


def hardware_members_amount(cluster: KubernetesCluster, group_name: str) -> None:
    beauty_name = group_name.capitalize()
    if group_name == 'vip':
        beauty_name = 'VIP'
    if group_name == 'all':
        beauty_name = 'Total Node'

    with TestCase(cluster, '005',  'Hardware', '%ss Amount' % beauty_name,
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


def hardware_cpu(cluster: KubernetesCluster, group_name: str) -> None:
    minimal_cpu = cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'] \
        if group_name == 'balancer' or cluster.nodes['all'].nodes_amount() > 1 \
        else cluster.globals['compatibility_map']['hardware']['minimal']['control-plane']['vcpu']
    with TestCase(cluster, '006',  'Hardware', 'VCPUs Amount - %ss' % group_name.capitalize(),
                  minimal=minimal_cpu,
                  recommended=cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']) as tc:
        if cluster.nodes.get(group_name) is None or cluster.nodes[group_name].is_empty():
            return tc.success(results='Skipped')
        results = cluster.nodes[group_name].sudo("nproc --all")
        cluster.log.verbose(results)
        minimal_amount: Optional[int] = None
        for host, result in results.items():
            amount = int(result.stdout)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < minimal_cpu:
                cluster.log.error('%s node %s has insufficient VCPUs: expected %s, but %s found.'
                                  % (group_name.capitalize(), host, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'], amount))
            elif amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']:
                cluster.log.warning('%s node %s has less VCPUs than recommended: recommended %s, but %s found.'
                                    % (group_name.capitalize(), host, cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu'], amount))
            else:
                cluster.log.debug('%s node %s has enough VCPUs: %s' % (group_name.capitalize(), host, amount))

        s = ''
        if minimal_amount != 1:
            s = 's'

        if minimal_amount < minimal_cpu:
            raise TestFailure("Less than minimal. Detected %s VCPU%s" % (minimal_amount, s),
                              hint="Increase the number of VCPUs in the node configuration to at least the minimum "
                                   "value: %s VCPUs." % cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['vcpu'])
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu']:
            raise TestWarn("Less than recommended. Detected %s VCPU%s" % (minimal_amount, s),
                           hint="Increase the number of VCPUs in the node configuration up to %s VCPUs."
                                % cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['vcpu'])
        tc.success(results='%s VCPU%s' % (minimal_amount, s))


def hardware_ram(cluster: KubernetesCluster, group_name: str) -> None:
    with TestCase(cluster, '007',  'Hardware', 'RAM Amount - %ss' % group_name.capitalize(),
                  minimal=cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'],
                  recommended=cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']) as tc:
        if cluster.nodes.get(group_name) is None or cluster.nodes[group_name].is_empty():
            return tc.success(results='Skipped')
        results = cluster.nodes[group_name].sudo("cat /proc/meminfo | awk '/DirectMap/ { print $2 }'")
        cluster.log.verbose(results)
        minimal_amount: Optional[int] = None
        for host, result in results.items():
            amount = math.floor(sum(map(lambda x: int(x), result.stdout.strip().split("\n"))) / 1000000)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram']:
                cluster.log.error('%s node %s has insufficient RAM: expected %sGB, but %sGB found.'
                                  % (group_name.capitalize(), host, cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'], amount))
            elif amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']:
                cluster.log.warning('%s node %s has less RAM than recommended: recommended %sGB, but %sGB found.'
                                    % (group_name.capitalize(), host, cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram'], amount))
            else:
                cluster.log.debug('%s node %s has enough RAM: %sGB' % (group_name.capitalize(), host, amount))
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram']:
            raise TestFailure("Less than minimal. Detected %sGB" % minimal_amount,
                              hint="Increase the number of RAM in the node configuration to at least the minimum "
                                   "value: %sGB." % cluster.globals['compatibility_map']['hardware']['minimal'][group_name]['ram'])
        if minimal_amount < cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram']:
            raise TestWarn("Less than recommended. Detected %sGB" % minimal_amount,
                           hint="Increase the number of RAM in the node configuration up to %s GB."
                                % cluster.globals['compatibility_map']['hardware']['recommended'][group_name]['ram'])
        tc.success(results='%sGB' % minimal_amount)


def system_distributive(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '008', 'System', 'Distibutive') as tc:
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
        
        os_ids = cluster.get_os_identifiers()
        different_os = set(os_ids.values())
        if len(different_os) > 1:
            cluster.log.warning(
                f"Nodes have different OS families or versions. "
                f"List of (OS family, version): {list(different_os)}")
            raise TestWarn(f"Nodes have different OS families or versions")
        
        tc.success(results=", ".join(detected_supported_os))


def check_kernel_version(cluster: KubernetesCluster) -> None:
    """
    This method compares the linux kernel version with the bad version
    """
    with TestCase(cluster, '015', "Software", "Kernel version") as tc:
        bad_results = {}
        unstable_kernel_ubuntu: List[str] = cluster.globals['compatibility_map']['distributives']['ubuntu'][0].get('unstable_kernel')
        unstable_kernel_centos: List[str] = []
        group = cluster.nodes['all']
        result_group = group.run('uname -r')
        for host, results in result_group.items():
            os_name = cluster.context['nodes'][host]['os']['name']
            result = results.stdout.rstrip()
            if os_name == 'ubuntu':
                if result in unstable_kernel_ubuntu:
                    bad_results[host] = result
            elif os_name == 'centos':
                if result in unstable_kernel_centos:
                    bad_results[host] = result

        if len(bad_results) > 0:
            for host, kernel_version in bad_results.items():
                cluster.log.debug(f"Unstable kernel %s on: %s" % (kernel_version, host))
            cluster.log.debug(f"Update the linux kernel version to 5.4.0-135-generic")
            raise TestWarn("Kernel version unstable")
        else:
            tc.success("All kernel have stable versions")


def check_access_to_thirdparties(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '012', 'Software', 'Thirdparties Availability') as tc:
        detect_preinstalled_python(cluster)
        broken = []
        nodes_without_python = set()

        # Load script for checking sources
        all_group = cluster.nodes['all']
        check_script = utils.read_internal("resources/scripts/check_url_availability.py")
        random_temp_path = "/tmp/%s.py" % uuid.uuid4().hex
        all_group.put(io.StringIO(check_script), random_temp_path)

        for destination, config in cluster.inventory['services'].get('thirdparties', {}).items():
            # Check if curl
            if config['source'][:4] != 'http' or '://' not in config['source'][4:8]:
                continue
            # Check with script
            common_group = cluster.create_group_from_groups_nodes_names(config.get('groups', []), config.get('nodes', []))
            for node in common_group.get_ordered_members_list():
                host = node.get_host()
                if cluster.context['nodes'][host]['python'] == "Not installed":
                    nodes_without_python.add(host)
                    continue
                python_executable = cluster.context['nodes'][host]['python']['executable']
                res = node.run("%s %s %s %s" % (python_executable, random_temp_path, config['source'],
                                                cluster.inventory['globals']['timeout_download']), warn=True)
                if res.is_any_failed():
                    broken.append(f"{host}, {destination}: {res[host].stderr}")

        # Remove file
        rm_command = "rm %s" % random_temp_path
        all_group.run(rm_command)

        if broken:
            raise TestFailure('Required thirdparties are unavailable', hint=yaml.safe_dump(broken))
        if nodes_without_python:
            raise TestWarn("Can't detect python version for some nodes, procedure can't be performed for them",
                           hint=yaml.safe_dump(list(nodes_without_python)))
        tc.success('All thirdparties are available')


def check_resolv_conf(cluster: KubernetesCluster) -> None:
    nodes_context = cluster.context['nodes']
    hosts = [host for host, node_context in nodes_context.items() if 'resolv_conf_is_actual' not in node_context]
    group = cluster.make_group(hosts)

    if cluster.inventory["services"].get("resolv.conf") is None:
        for host in hosts:
            nodes_context[host]["resolv_conf_is_actual"] = True
    else:
        # Create temp resolv.conf file
        resolv_conf_buffer = system.get_resolv_conf_buffer(cluster.inventory["services"].get("resolv.conf"))
        random_resolv_conf_path = "/tmp/%s.conf" % uuid.uuid4().hex
        group.put(resolv_conf_buffer, random_resolv_conf_path)

        # Compare with existed resolv.conf
        results = group.run(
            '[ -f /etc/resolv.conf ] && '
            'cmp --silent /etc/resolv.conf %s' % random_resolv_conf_path,
            warn=True)

        for host, res in results.items():
            nodes_context[host]["resolv_conf_is_actual"] = not res.failed
        # Remove temp resolv.conf file
        group.run("rm %s" % random_resolv_conf_path)


def check_package_repositories(cluster: KubernetesCluster) -> None:
    nodes_context = cluster.context['nodes']
    hosts = [host for host, node_context in nodes_context.items() if 'package_repos_are_actual' not in node_context]

    repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
    if repositories is None:
        for host in hosts:
            nodes_context[host]["package_repos_are_actual"] = True
    else:
        group = cluster.make_group(hosts)
        random_repos_conf_path = "/tmp/%s.repo" % uuid.uuid4().hex
        collector = CollectorCallback(cluster)
        with group.new_executor() as exe:
            for node in exe.group.get_ordered_members_list():
                # Create temp repos file
                packages.create_repo_file(node, repositories, random_repos_conf_path)

                # Compare with existed resolv.conf
                predefined_repos_file = packages.get_repo_filename(node)
                node.sudo(
                    '[ -f %s ] && cmp --silent %s %s' %
                    (predefined_repos_file, predefined_repos_file, random_repos_conf_path),
                    warn=True, callback=collector)

        for host, result in collector.result.items():
            nodes_context[host]["package_repos_are_actual"] = not result.failed

        # Remove temp .repo file
        group.sudo("rm %s" % random_repos_conf_path)


def check_access_to_package_repositories(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '013', 'Software', 'Package Repositories') as tc:
        detect_preinstalled_python(cluster)
        check_resolv_conf(cluster)
        broken = []
        warnings = []

        # Collect repository urls
        # TODO: think about better parsing
        repository_urls: List[str] = []
        repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
        if cluster.get_os_family() not in ['debian', 'rhel', 'rhel8', 'rhel9']:
            # Skip check in case of multiply or unknown OS
            raise TestWarn("Can't check package repositories on multiply OS")
        if isinstance(repositories, list):
            # For debian
            for repo in repositories:
                repository_url = list(filter(lambda x: x[:4] == 'http' and '://' in x[4:8], repo.split(' ')))
                if repository_url:
                    repository_urls.append(repository_url[0])
                else:
                    broken.append(f"Found broken repository: '{repo}'")
        elif isinstance(repositories, dict):
            # For rhel
            for repo_name, repo_conf in repositories.items():
                if repo_conf.get('baseurl') is not None:
                    repository_urls.append(repo_conf.get('baseurl'))
                else:
                    broken.append(f"Found broken repository: '{repo_name}'")
        elif isinstance(repositories, str):
            path = utils.get_external_resource_path(repositories)
            if not os.path.isfile(path):
                broken.append(f"File {path} with the repositories content does not exist")
            else:
                repositories = utils.read_external(path)
                for repo in repositories.split('\n'):
                    repository_url = list(filter(lambda x: x[:4] == 'http' and '://' in x[4:8], repo.split(' ')))
                    if repository_url:
                        repository_urls.append(repository_url[0])
                if not repository_urls:
                    broken.append(f"Failed to detect repository URLs in file {path}")

        repository_urls = list(set(repository_urls))
        cluster.log.debug(f"Repositories to check: {repository_urls}")

        # Load script for checking sources
        all_group = cluster.nodes['all']
        check_script = utils.read_internal("resources/scripts/check_url_availability.py")
        random_temp_path = "/tmp/%s.py" % uuid.uuid4().hex
        all_group.put(io.StringIO(check_script), random_temp_path)

        if repository_urls:
            collector = CollectorCallback(cluster)
            with all_group.new_executor() as exe:
                for node in exe.group.get_ordered_members_list():
                    host = node.get_host()
                    # Check with script
                    if cluster.context['nodes'][host]['python'] == 'Not installed':
                        warnings.append(f"Can't detect python version for node {host}, "
                                        f"operation can't be performed for it")
                        continue
                    python_executable = cluster.context['nodes'][host]['python']['executable']
                    for repo_url in repository_urls:
                        node.run('%s %s %s %s'
                                 % (python_executable, random_temp_path, repo_url,
                                    cluster.inventory['globals']['timeout_download']),
                                 warn=True, callback=collector)

            for host, url_results in collector.results.items():
                # Check if resolv.conf is actual
                resolv_conf_actual = cluster.context['nodes'][host]['resolv_conf_is_actual']
                if not resolv_conf_actual:
                    warnings.append(f"resolv.conf is not installed for node {host}: "
                                    f"Package repositories can be unavailable. You can install resolv.conf using task "
                                    f"`install --tasks prepare.dns.resolv_conf`")
                    problem_handler = warnings
                else:
                    problem_handler = broken
                for i, result in enumerate(url_results):
                    if result.failed:
                        problem_handler.append(f"{host}, {repository_urls[i]}: {result.stderr}")

        # Remove file
        rm_command = "rm %s" % random_temp_path
        all_group.run(rm_command)

        if broken:
            raise TestFailure('Found problems for package repositories', hint=yaml.safe_dump(broken))
        elif warnings:
            raise TestWarn('Found potential problems for package repositories or nodes', hint=yaml.safe_dump(warnings))
        tc.success('All package repositories are correct and available')


def check_access_to_packages(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '014', 'Software', 'Package Availability') as tc:
        check_package_repositories(cluster)
        broken: List[str] = []
        warnings: List[str] = []
        group = cluster.nodes['all']
        hosts_to_packages = packages.get_all_managed_packages_for_group(group, cluster.inventory)
        collector = CollectorCallback(cluster)
        with group.new_executor() as exe:
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                packages_to_check = list(set(hosts_to_packages[host]))
                hosts_to_packages[host] = packages_to_check
                cluster.log.debug(f"Packages to check for node {host}: {packages_to_check}")

                for package in packages_to_check:
                    packages.search_package(node, package, callback=collector)

        # Check packages from install section
        for host, results in collector.results.items():
            package_repos_are_actual = cluster.context['nodes'][host]["package_repos_are_actual"]
            if not package_repos_are_actual:
                warnings.append(f"Package repositories are not installed for {host}: "
                                f"Packages can be unavailable. You can install it using tasks "
                                f"`install --tasks prepare.dns.resolv_conf,prepare.package_manager.configure`")
                problem_handler = warnings
            else:
                problem_handler = broken
            packages_to_check = hosts_to_packages[host]
            for i, result in enumerate(results):
                if result.failed:
                    problem_handler.append(f"Package {packages_to_check[i]} is unavailable for node {host}")

        if broken:
            raise TestFailure('Required packages are unavailable', hint=yaml.safe_dump(broken))
        elif warnings:
            raise TestWarn('Found potential problems for packages', hint=yaml.safe_dump(warnings))
        tc.success('All packages are available')


def detect_preinstalled_python(cluster: KubernetesCluster) -> None:
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

    for host, result in detected_python.items():
        identity = result.stdout.strip()
        if not identity:
            nodes_context[host]["python"] = "Not installed"
        else:
            executable, version = tuple(identity.splitlines())
            version = cast(Match[str], re.match(python_version_pattern, version)).group(1)
            nodes_context[host]["python"] = {
                "executable": executable,
                "major_version": version
            }


@contextmanager
def suspend_firewalld(cluster: KubernetesCluster) -> Iterator[None]:
    firewalld_statuses = system.fetch_firewalld_status(cluster.nodes["all"])
    stop_firewalld_group = firewalld_statuses.get_nodes_group_where_value_in_stdout("active (running)")

    nodes_to_rollback = cluster.make_group([])
    try:
        try:
            nodes_to_rollback = system.stop_service(stop_firewalld_group, "firewalld").get_group()
        except GroupException as e:
            nodes_to_rollback = e.get_exited_nodes_group()
            raise

        yield
    finally:
        system.start_service(nodes_to_rollback, "firewalld")


def get_host_network_ports(_: KubernetesCluster) -> Dict[str, Set[str]]:
    """
    :return: ports bound to host network for each cluster role
    """
    return {
        'balancer': {'80', '443', '6443'},
        'control-plane': {'6443', '10250', '2379', '2380', '179', '9091'},
        'worker': {'10250', '179', '5473', '9091', '9093'},
    }


def get_ports_connectivity(cluster: KubernetesCluster, proto: str) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    if proto in _CONNECTIVITY_PORTS:
        return _CONNECTIVITY_PORTS[proto]

    random_node_port = str(random.randint(30000, 32767))
    random_user_port = str(random.randint(1024, 65535))
    if proto == 'tcp':
        target_ports = cluster.inventory['services']['loadbalancer']['target_ports']
        ingress_ports = [str(target_ports['http']), str(target_ports['https'])]
        connectivity_ports = {
            'internal': {
                'input': {
                    'balancer': ['80', '443', '6443'],
                    'control-plane': [
                        '53', '6443', '10250', '2379', '2380', '179',
                        '9091', '9093',  # Calico metrics on host ports
                        '5473',  # If calico-typha is enabled
                        '5443',  # calico-apiserver, if enabled.
                        random_node_port,
                    ],
                    'worker': [
                        '53', '10250', '179',
                        '8443',  # Ingress NGINX validating webhook
                        '5443',  # calico-apiserver, if enabled.
                        '5473',  # If calico-typha is enabled
                        '9091', '9093',  # Calico metrics on host ports
                        random_node_port,
                    ] + ingress_ports,
                },
                'output': {
                    'balancer': [
                        '80', '443',  # This only way we can check balancers connectivity
                        '6443',
                        random_node_port,  # Maybe custom balancing of NodePorts
                    ] + ingress_ports,
                    'control-plane': [
                        '80', '443',  # This only way we can check balancers connectivity
                        '53', '6443', '10250', '2379', '2380', '179',
                        '5443',  # calico-apiserver, if enabled.
                        '5473',  # If calico-typha is enabled
                        '8443',  # Ingress NGINX validating webhook
                    ],
                    'worker': [
                        '80', '443',  # This only way we can check balancers connectivity
                        '53', '6443', '179',
                        '5473',  # If calico-typha is enabled
                        '9091', '9093',  # Calico metrics on host ports
                    ]
                }
            },
            # Check only some ports. In fact, it is desirable to allow all ports for pod subnet
            'pod': {
                'input': {
                    'control-plane': [
                        '53',
                        '9094',  # calico-kube-controllers metrics
                        random_user_port,
                    ],
                    'worker': [
                        '53',
                        '9094',  # calico-kube-controllers metrics
                        '8443',  # Kubernetes dashboard, if installed
                        '10254',  # Ingress NGINX metrics
                        random_user_port,
                    ],
                },
                'output': {
                    'control-plane': ['53', random_user_port],
                    'worker': [
                        '53',
                        '9094',  # calico-kube-controllers metrics
                        '8443',  # Kubernetes dashboard, if installed
                        '10254',  # Ingress NGINX metrics
                        random_user_port,
                    ],
                }
            },
            'service': {
                'input': {
                    'control-plane': [random_user_port],
                    'worker': [random_user_port],
                },
                'output': {
                    'control-plane': [random_user_port],
                    'worker': [random_user_port],
                }
            }
        }

    else:  # udp
        connectivity_ports = {
            'internal': {
                'input': {
                    'control-plane': ['53'],
                    'worker': ['53']
                },
                'output': {
                    'control-plane': ['53'],
                    'worker': ['53']
                }
            },
            'pod': {
                'input': {
                    'control-plane': ['53'],
                    'worker': ['53'],
                },
                'output': {
                    'control-plane': ['53'],
                    'worker': ['53']
                }
            },
        }

    _CONNECTIVITY_PORTS[proto] = connectivity_ports
    return connectivity_ports


def get_input_ports(cluster: KubernetesCluster, group: NodeGroup, subnet_type: str, proto: str) -> Dict[str, List[str]]:
    connectivity_ports = get_ports_connectivity(cluster, proto).get(subnet_type, {}).get('input', {})

    host_ports: Dict[str, OrderedSet[str]] = {}
    for node in group.get_ordered_members_configs_list():
        host = node['connect_to']
        for role in node['roles']:
            ports = connectivity_ports.get(role, [])
            if ports:
                host_ports.setdefault(host, OrderedSet[str]()).update(ports)

    return {host: list(ports) for host, ports in host_ports.items()}


@contextmanager
def assign_ips(group: NodeGroup,
               host_to_ip: Dict[str, str], host_to_inf: Dict[str, str],
               prefix: int) -> Iterator[None]:
    group_to_rollback = group
    try:
        # Create alias from the node network interface for the subnet on every node
        try:
            with group.new_executor() as exe:
                for node in exe.group.get_ordered_members_list():
                    host = node.get_host()
                    node.sudo(f"ip a add {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}")
        except GroupException as e:
            group_to_rollback = e.get_exited_nodes_group()
            raise

        yield
    finally:
        # Remove the created aliases from network interfaces
        with group_to_rollback.new_executor() as exe:
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                node.sudo(f"ip a del {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}",
                          warn=True)


@contextmanager
def assign_random_ips(cluster: KubernetesCluster, group: NodeGroup, host_to_inf: Dict[str, str], subnet: str) -> Iterator[Dict[str, str]]:
    cluster.log.debug(f"Assigning random IP addresses from {subnet} to the internal interface...")

    inet = ipaddress.ip_network(subnet)
    prefix = inet.prefixlen
    broadcast = int(inet.broadcast_address)

    host_to_ip = {}

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        # Assign random IP for the subnet on every node
        i = 30
        for node in exe.group.get_ordered_members_list():
            host = node.get_host()
            random_host = str(ipaddress.ip_address(broadcast - i))
            host_to_ip[host] = random_host
            i = i + 1

            existing_alias = f"ip -o a | grep {host_to_inf[host]} | grep {host_to_ip[host]}"
            node.sudo(existing_alias, warn=True, callback=collector)

    group = group.new_group(
        apply_filter=lambda node_config: collector.result[node_config['connect_to']].grep_returned_nothing()
    )
    with assign_ips(group, host_to_ip, host_to_inf, prefix):
        yield host_to_ip


def get_active_interfaces(cluster: KubernetesCluster) -> Dict[str, str]:
    host_to_inf = {}
    no_active_interfaces = []
    for host in cluster.nodes['all'].get_hosts():
        inf = cluster.context['nodes'][host].get('active_interface')
        if not inf:
            no_active_interfaces.append(host)
        else:
            host_to_inf[host] = inf

    if no_active_interfaces:
        hint = f"Failed to detect active interface " \
               f"on nodes: {', '.join(cluster.make_group(no_active_interfaces).get_nodes_names())}."
        raise TestFailure('Failed', hint=hint)

    return host_to_inf


def subnet_connectivity(cluster: KubernetesCluster, subnet_type: str) -> None:
    subnet = cluster.inventory['services']['kubeadm']['networking'][
        'podSubnet' if subnet_type == 'pod' else 'serviceSubnet'
    ]
    cluster.log.debug(f"Checking connectivity for the {subnet_type} subnet {subnet}")

    skipped_msgs = nodes_require_python(cluster)
    group = cluster.make_group_from_roles(['control-plane', 'worker'])\
        .intersection_group(get_python_group(cluster, True))

    mtu = get_mtu(cluster)
    host_to_inf = get_active_interfaces(cluster)
    with assign_random_ips(cluster, group, host_to_inf, subnet) as host_to_ip:
        failed_nodes: Set[str] = set()
        for proto in ('tcp', 'udp'):
            host_ports = get_input_ports(cluster, group, subnet_type, proto)
            with install_listeners(cluster, host_ports, host_to_ip, proto, mtu) as listened_ports:
                failed_nodes.update(check_connect_between_all_nodes(
                    cluster, listened_ports, host_to_ip, subnet_type, proto, mtu))

        if failed_nodes:
            hint = f"Traffic is not allowed for the {subnet_type} subnet {subnet} " \
                   f"on nodes: {', '.join(cluster.make_group(failed_nodes).get_nodes_names())}."
            raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                              hint=hint)

    if skipped_msgs:
        raise TestWarn("Cannot complete check", hint='\n'.join(skipped_msgs))


def pod_subnet_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '009', 'Network', 'PodSubnet', default_results='Connected'),\
            suspend_firewalld(cluster):
        subnet_connectivity(cluster, 'pod')


def service_subnet_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '010', 'Network', 'ServiceSubnet', default_results='Connected'),\
            suspend_firewalld(cluster):
        subnet_connectivity(cluster, 'service')


def cmd_for_ports(ports: List[str], query: str) -> str:
    result = ""
    for port in ports:
        result += f" && echo 'port: {port}' && ( {query % port} ) "
    return result[3:]


def get_mtu(cluster: KubernetesCluster) -> int:
    mtu: int = cluster.inventory['plugins']['calico']['mtu']
    # 40 bites for headers
    mtu -= 40
    return mtu


def port_connect(cluster: KubernetesCluster, port_client: str,
                 node: DeferredGroup, payload: Tuple[str, str, bool],
                 host_to_ip: Dict[str, str], timeout: int) -> None:
    target_host, port, connect_only = payload
    cluster.log.verbose(f"Trying connection from {node.get_node_name()!r} "
                        f"to {cluster.get_node_name(target_host)!r} by port {port}")

    python_executable = cluster.context['nodes'][node.get_host()]['python']['executable']
    # Do not send random stream of bytes if port is already in use,
    # and test listener is not installed.
    # Also, do not send random stream of bytes for Kubernetes managed ports,
    # that are not listened on host network.
    # Such traffic may not reach the test listener even if it was installed successfully,
    # as the target address may be translated into the pod address.
    connect_only = connect_only or all(
        port not in get_host_network_ports(cluster).get(role, [])
        for role in cluster.get_node(target_host)['roles']
    )
    action = 'connect' if connect_only else 'send'

    address = host_to_ip[target_host]
    ip_version = ipaddress.ip_address(address).version

    # For UDP, `action` is ignored and random stream of bytes is sent anyway.
    # Currently, for 53 port we do not expect any addressee except the test listener.
    cmd = f"{python_executable} {port_client} {action} {port} {address} {ip_version}"
    node.sudo(cmd, timeout=timeout)


def get_start_listener_cmd(python_executable: str, port_listener: str) -> str:
    # 1. Create anonymous pipe
    # 2. Create python listener process in background and redirect output to pipe
    # 3. Wait till the listener fails and exits, or till it responds with message
    # 4. Read the remained data from pipe in non-blocking mode
    # 5. Exit with success or fail depending on what was received from pipe
    return "PORT=%s; PIPE=$(mktemp -u); mkfifo $PIPE; exec 3<>$PIPE; rm $PIPE; " \
           f"sudo nohup {python_executable} {port_listener} $PORT >&3 2>&1 & " \
           "PID=$(echo $!); " \
           "while sudo kill -0 $PID 2>/dev/null ; do " \
               "DATA=$(dd iflag=nonblock status=none <&3 2>/dev/null) ; " \
               "if [[ -n $DATA ]]; then break; else sleep 0.1; fi; " \
           "done; " \
           "DATA=$(echo -n \"$DATA\" && dd iflag=nonblock status=none <&3 2>/dev/null); " \
           "if [[ $DATA == \"In use\" ]]; then " \
               "echo \"$PORT in use\" >&2 ; " \
               "exit 0; " \
           "elif [[ $DATA == \"Listen\" ]]; then " \
               "exit 0; " \
           "fi; " \
           "echo -n \"$DATA\" >&2 ; " \
           "exit 1"


def get_stop_listener_cmd(port_listener: str) -> str:
    identify_pid = f"ps aux | grep \" {port_listener} ${{port}}$\" " \
                   f"| grep -v grep | grep -v nohup | awk '{{print $2}}'"
    return f"port=%s;pid=$({identify_pid}) " \
           "&& if [ ! -z $pid ]; then sudo kill -9 $pid; echo \"killed pid $pid for port $port\"; fi"


def install_client(cluster: KubernetesCluster, group: DeferredGroup, proto: str, mtu: int, timeout: int) -> str:
    check_script = utils.read_internal('resources/scripts/simple_port_client.py')
    udp_client = "/tmp/%s.py" % uuid.uuid4().hex
    for node in group.get_ordered_members_list():
        rendered_script = jinja.new(cluster.log).from_string(check_script).render({
            'proto': proto,
            'timeout': timeout,
            'mtu': mtu,
        })
        node.put(io.StringIO(rendered_script), udp_client)

    group.flush()

    return udp_client


def check_connect_between_all_nodes(cluster: KubernetesCluster,
                                    host_ports: Dict[str, List[Tuple[str, bool]]], host_to_ip: Dict[str, str],
                                    subnet_type: str, proto: str, mtu: int) -> Dict[str, List[str]]:
    if not host_ports:
        return {}

    logger = cluster.log
    logger.debug(f"Checking {proto.upper()} connectivity between nodes...")

    group = get_python_group(cluster, True).new_defer()
    timeout = static.GLOBALS['connection']['defaults']['timeout']
    port_client = install_client(cluster, group, proto, mtu, timeout)

    connectivity_ports = get_ports_connectivity(cluster, proto).get(subnet_type, {}).get('output', {})

    # Check connectivity from all nodes to each listened port of each specified host.
    connectivity_payloads: Dict[str, OrderedSet[Tuple[str, str, bool]]] = {}

    def remove_payload(host: str, payload: Tuple[str, str, bool]) -> None:
        payloads = connectivity_payloads.get(host)
        if payloads is None:
            return

        payloads.discard(payload)
        if not payloads:
            del connectivity_payloads[host]

    for node in group.get_ordered_members_list():
        host = node.get_host()
        output_ports = {port for role in node.get_config()['roles'] for port in connectivity_ports.get(role, [])}
        for target_host, listen_ports in host_ports.items():
            if host == target_host:
                continue

            for listen_port, in_use in listen_ports:
                if listen_port in output_ports:
                    connectivity_payloads.setdefault(host, OrderedSet[Tuple[str, str, bool]]())\
                        .add((target_host, listen_port, in_use))

    failures = 0
    failures_limit = 10
    failed_ports: Dict[str, OrderedSet[str]] = {}

    while connectivity_payloads:
        payloads_chunk: Dict[str, Tuple[str, str, bool]] = {}
        for node in group.get_ordered_members_list():
            host = node.get_host()
            payloads = connectivity_payloads.get(host)
            if payloads is None:
                continue

            # Try making unique target (host, port) pairs in each chunk
            payload = next((p for p in payloads if p not in payloads_chunk.values()), payloads[0])
            remove_payload(host, payload)
            payloads_chunk[host] = payload

        failed_payloads = nodes_ports_connect(cluster, port_client, payloads_chunk, host_to_ip, timeout)
        if failed_payloads:
            failures += 1
            for host, payload in failed_payloads.items():
                target_host, listen_port, _ = payload
                cluster.log.error(f"Subnet connectivity test failed from '{cluster.get_node_name(host)}' "
                                  f"to '{cluster.get_node_name(target_host)}' by {proto.upper()} port {listen_port}")

                failed_ports.setdefault(target_host, OrderedSet[str]()).add(listen_port)

                # If at least one node failed to connect to the given target host and port,
                # no need to attempt to do that from other nodes
                for host in group.get_hosts():
                    remove_payload(host, payload)

        if failures == failures_limit:
            logger.debug("Exceeded limit of failed connectivity checks. Further check is skipped.")
            break

    return {host: list(ports) for host, ports in failed_ports.items()}


def nodes_ports_connect(cluster: KubernetesCluster, port_client: str,
                        payloads: Dict[str, Tuple[str, str, bool]],
                        host_to_ip: Dict[str, str], timeout: int) -> Dict[str, Tuple[str, str, bool]]:
    group = cluster.make_group(payloads).new_defer()

    for node in group.get_ordered_members_list():
        host = node.get_host()
        payload = payloads[host]
        port_connect(cluster, port_client, node, payload, host_to_ip, timeout)

    failed_payloads = {}
    try:
        group.flush()
    except GroupException as e:
        cluster.log.verbose(e)
        excepted_hosts = e.get_excepted_hosts_list()
        failed_payloads = {host: payload for host, payload in payloads.items() if host in excepted_hosts}

    return failed_payloads


def get_python_group(cluster: KubernetesCluster, has_python: bool) -> NodeGroup:
    def filter_(node: NodeConfig) -> bool:
        python_spec: Union[dict, str] = cluster.context['nodes'][node['connect_to']]['python']
        return has_python == (python_spec != "Not installed")

    return cluster.nodes['all'].new_group(filter_)


def nodes_require_python(cluster: KubernetesCluster) -> List[str]:
    detect_preinstalled_python(cluster)
    group_no_python = get_python_group(cluster, False)

    if not group_no_python.is_empty():
        msg = f"Nodes without python: {', '.join(group_no_python.get_nodes_names())}"
        cluster.log.warning(msg)

        return [msg]

    return []


@contextmanager
def install_listeners(cluster: KubernetesCluster,
                      host_ports: Dict[str, List[str]], host_to_ip: Dict[str, str],
                      proto: str, mtu: int) -> Iterator[Dict[str, List[Tuple[str, bool]]]]:
    logger = cluster.log
    logger.debug(f"Installing {proto.upper()} listeners on nodes...")

    group = cluster.make_group(host_ports)
    # currently port listener can be run on both python 2 and 3
    check_script = utils.read_internal('resources/scripts/simple_port_listener.py')
    port_listener = "/tmp/%s.py" % uuid.uuid4().hex

    listened_ports: Dict[str, List[Tuple[str, bool]]] = {}
    try:
        collector = CollectorCallback(cluster)
        with group.new_executor() as exe:
            # Run processes that listen TCP or UDP ports
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                bind_address = host_to_ip[host]
                ip_version = ipaddress.ip_address(bind_address).version
                rendered_script = jinja.new(logger).from_string(check_script).render({
                    'proto': proto,
                    'address': bind_address,
                    'ip_version': ip_version,
                    'mtu': mtu,
                })
                node.put(io.StringIO(rendered_script), port_listener)

                python_executable = cluster.context['nodes'][host]['python']['executable']
                port_start_listener_cmd = get_start_listener_cmd(python_executable, port_listener)
                listener_cmd = cmd_for_ports(host_ports[host], port_start_listener_cmd)
                node.sudo(listener_cmd, callback=collector)

        port_in_use_ptrn = re.compile(r'^(\d+) in use$')
        for host, result in collector.result.items():
            ports_in_use = []
            if result.stderr:
                for msg in result.stderr.rstrip('\n').split('\n'):
                    matcher = port_in_use_ptrn.match(msg)
                    if matcher is None:
                        raise GroupResultException(collector.result)
                    else:
                        port = matcher.group(1)
                        ports_in_use.append(port)
                        logger.verbose(f"{proto.upper()} port {port} is already in use on {cluster.get_node_name(host)}")

            for port in host_ports[host]:
                in_use = port in ports_in_use
                listened_ports.setdefault(host, []).append((port, in_use))

        yield listened_ports

    finally:
        with group.new_executor() as exe:
            # Kill the processes created during the test
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                port_stop_listener_cmd = get_stop_listener_cmd(port_listener)
                listener_cmd = cmd_for_ports(host_ports[host], port_stop_listener_cmd)
                node.sudo(listener_cmd, warn=True)


def ports_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '011', 'Network', 'TCP & UDP Ports', default_results='Connected'),\
            suspend_firewalld(cluster):
        skipped_msgs = nodes_require_python(cluster)
        failed_nodes: Set[str] = set()
        failed_msgs: List[str] = []

        group = get_python_group(cluster, True)

        host_to_ip = {node['connect_to']: node['internal_address'] for node in group.get_ordered_members_configs_list()}
        mtu = get_mtu(cluster)
        for proto in ('tcp', 'udp'):
            cluster.log.debug(f"Checking {proto.upper()} ports connectivity")
            host_ports = get_input_ports(cluster, group, 'internal', proto)
            with install_listeners(cluster, host_ports, host_to_ip, proto, mtu) as listened_ports:
                failed_ports = check_connect_between_all_nodes(
                    cluster, listened_ports, host_to_ip, 'internal', proto, mtu)
                failed_nodes.update(failed_ports)
                failed_msgs.extend(
                    f"{proto.upper()} ports not opened for internal traffic on {cluster.get_node_name(host)}: {', '.join(ports)}"
                    for host, ports in failed_ports.items())

        if failed_msgs:
            raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                              hint='\n'.join(failed_msgs))

        if skipped_msgs:
            raise TestWarn("Cannot complete check", hint='\n'.join(skipped_msgs))


def vips_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '016', 'Network', 'VRRP IPs') as tc,\
            suspend_firewalld(cluster):
        logger = cluster.log
        keepalived_group = cluster.make_group_from_roles(['keepalived'])
        if keepalived_group.is_empty():
            return tc.success(results='Skipped')

        skipped_msgs = nodes_require_python(cluster)
        failed_nodes: Set[str] = set()
        failed_msgs: List[str] = []

        keepalived_group = keepalived_group.intersection_group(get_python_group(cluster, True))
        mtu = get_mtu(cluster)

        for item in cluster.inventory['vrrp_ips']:
            ip = item['ip']
            node_names = [record['name'] for record in item['hosts']]
            group = keepalived_group.new_group(apply_filter={'name': node_names})
            if group.is_empty():
                logger.debug(f"Skipping VRRP IP {ip} as it is not assigned to any balancer with python installed.")
                continue

            logger.debug(f"Checking TCP ports connectivity to VRRP IP {ip}")
            vip_assigned_balancer = next((
                host
                for host, result in group.sudo(f"ip -o a | grep {ip}", warn=True).items()
                if not result.grep_returned_nothing()
            ), None)

            if vip_assigned_balancer is not None:
                logger.debug(f"VRRP IP is already assigned to balancer {cluster.get_node_name(vip_assigned_balancer)}.")

            for record in item['hosts']:
                node_name = record['name']
                # Probably not existing hosts.name
                if not group.has_node(node_name):
                    continue

                node = group.get_member_by_name(node_name)
                host = node.get_host()

                if vip_assigned_balancer is not None and vip_assigned_balancer != host:
                    logger.debug(f"Skipping check on balancer {node_name} "
                                 f"as the VRRP IP {ip} is assigned to another balancer.")
                    continue

                logger.debug(f"Checking VRRP IP {ip} on balancer {node_name}...")

                host_to_inf = {host: record['interface']}
                host_to_ip = {host: ip}

                assign_ips_ctx: AbstractContextManager = nullcontext()
                if vip_assigned_balancer is None:
                    logger.debug(f"Assigning IP address {ip} to the internal interface on balancer {node_name}...")
                    get_python_group(cluster, True).exclude_group(node).sudo(f'ip neigh flush {ip}')

                    prefix = ipaddress.ip_address(ip).max_prefixlen
                    assign_ips_ctx = assign_ips(node, host_to_ip, host_to_inf, prefix)

                host_ports = {
                    host: list(get_ports_connectivity(cluster, 'tcp')['internal']['input']['balancer'])
                }
                with assign_ips_ctx, install_listeners(cluster, host_ports, host_to_ip, 'tcp', mtu) as listened_ports:
                    failed_ports = check_connect_between_all_nodes(
                        cluster, listened_ports, host_to_ip, 'internal', 'tcp', mtu)
                    failed_nodes.update(failed_ports)
                    failed_msgs.extend(
                        f"Ports not opened on {ip} when assigned to balancer {node_name}: {', '.join(ports)}"
                        for host, ports in failed_ports.items())

        if failed_msgs:
            raise TestFailure(f"Failed to connect to {len(failed_nodes)} nodes.",
                              hint='\n'.join(failed_msgs))

        if skipped_msgs:
            raise TestWarn("Cannot complete check", hint='\n'.join(skipped_msgs))

        tc.success(results='Connected')


def make_reports(context: dict) -> None:
    if not context['execution_arguments'].get('disable_csv_report', False):
        context['testsuite'].save_csv(context['execution_arguments']['csv_report'], context['execution_arguments']['csv_report_delimiter'])
    if not context['execution_arguments'].get('disable_html_report', False):
        context['testsuite'].save_html(context['execution_arguments']['html_report'], context['initial_procedure'].upper())


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
        'ports_connectivity': ports_connectivity,
        'vips_connectivity': vips_connectivity,
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
    },
    'software': {
        'kernel': {
            'version': check_kernel_version
        },
        'thirdparties': {
            'availability': check_access_to_thirdparties
        },
        'packages': {
            'repositories': check_access_to_package_repositories,
            'availability': check_access_to_packages
        }
    }
})


class IaasAction(Action):
    def __init__(self) -> None:
        super().__init__('check iaas')

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for checking Kubernetes cluster IAAS layer.
    
    Hot to use:

    '''

    parser = flow.new_tasks_flow_parser(cli_help, tasks=tasks)

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

    context = flow.create_context(parser, cli_arguments, procedure='check_iaas')
    context['testsuite'] = TestSuite()
    context['preserve_inventory'] = False

    return context


def main(cli_arguments: List[str] = None) -> TestSuite:
    context = create_context(cli_arguments)
    flow_ = flow.ActionsFlow([IaasAction()])
    result = flow_.run_flow(context, print_summary=False)

    context = result.context
    testsuite: TestSuite = context['testsuite']

    # Final summary should be printed only to stdout with custom formatting
    # If test results are required for parsing, they can be found in the test results files
    print(testsuite.get_final_summary())
    testsuite.print_final_status(result.logger)
    make_reports(context)
    return testsuite


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
