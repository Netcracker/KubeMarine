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
import string
from collections import OrderedDict
import time
from contextlib import contextmanager, nullcontext, AbstractContextManager
from typing import List, Dict, cast, Match, Iterator, Optional, Tuple, Set, Union

import yaml
from jinja2 import Template
from ordered_set import OrderedSet

from kubemarine.core import flow, utils, static
from kubemarine import system, packages, thirdparties
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.errors import KME0006
from kubemarine.testsuite import TestSuite, TestCase, TestFailure, TestWarn
from kubemarine.core.group import (
    NodeConfig, NodeGroup, DeferredGroup, GroupException, GroupResultException, CollectorCallback
)

_CONNECTIVITY_PORTS: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]] = {}


def connection_ssh_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '001', 'SSH', 'Connectivity', default_results='Connected'):
        try:
            cluster.check_nodes_accessibility(skip_check_iaas=False)
        except KME0006 as e:
            raise TestFailure(e.summary, hint=e.details) from None


def connection_ssh_latency_single(cluster: KubernetesCluster) -> None:
    latency_cfg = static.GLOBALS['compatibility_map']['network']['connection']['latency']['single']
    with TestCase(cluster, '002',  'SSH', 'Latency - Single Thread',
                  minimal=latency_cfg['critical'],
                  recommended=latency_cfg['recommended']) as tc:
        i = 0
        measurements = []
        accessible_nodes = cluster.nodes['all'].get_accessible_nodes()
        if accessible_nodes.is_empty():
            return tc.success(results="Skipped")

        while i < 5:
            i += 1
            for node in accessible_nodes.get_ordered_members_list():
                time_start = time.time()
                node.run("echo 1")
                time_end = time.time()
                diff = (time_end - time_start) * 1000
                cluster.log.debug('Connection to %s - %sms' % (node.get_node_name(), diff))
                measurements.append(diff)
        average_latency = math.floor(sum(measurements) / accessible_nodes.nodes_amount() / 5)
        if average_latency > latency_cfg['critical']:
            raise TestFailure("Very high latency: %sms" % average_latency,
                              hint="A very high latency was detected between the deploy node and cluster nodes. "
                                   "Check your network settings and status. It is necessary to reduce the latency to %sms."
                                   % latency_cfg['critical'])
        if average_latency > latency_cfg['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="The detected latency is higher than the recommended value (%sms). Check your network settings "
                                "and status." % latency_cfg['recommended'])
        tc.success(results="%sms" % average_latency)


def connection_ssh_latency_multiple(cluster: KubernetesCluster) -> None:
    latency_cfg = static.GLOBALS['compatibility_map']['network']['connection']['latency']['multi']
    with TestCase(cluster, '003',  'SSH', 'Latency - Multi Thread',
                  minimal=latency_cfg['critical'],
                  recommended=latency_cfg['recommended']) as tc:
        i = 0
        measurements = []
        accessible_nodes = cluster.nodes['all'].get_accessible_nodes()
        if accessible_nodes.is_empty():
            return tc.success(results="Skipped")

        while i < 10:
            i += 1
            time_start = time.time()
            accessible_nodes.run("echo 1")
            time_end = time.time()
            diff = (time_end - time_start) * 1000
            cluster.log.debug('Average latency at step %s - %sms' % (i, diff))
            measurements.append(diff)
        average_latency = math.floor(sum(measurements) / 10)
        if average_latency > latency_cfg['critical']:
            raise TestFailure("Very high latency: %sms" % average_latency,
                              hint="A very high latency was detected between the deploy node and cluster nodes. "
                                   "Check your network settings and status. It is necessary to reduce the latency to %sms."
                                   % latency_cfg['critical'])
        if average_latency > latency_cfg['recommended']:
            raise TestWarn("High latency: %sms" % average_latency,
                           hint="The detected latency is higher than the recommended value (%sms). Check your network settings "
                                "and status." % latency_cfg['recommended'])
        tc.success(results="%sms" % average_latency)


def connection_sudoer_access(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '004', 'SSH', 'Sudoer Access', default_results='Access provided'):
        non_root = []
        for host, node_context in cluster.nodes_context.items():
            access_info = node_context['access']
            if access_info['online'] and access_info['sudo'] == 'Root':
                cluster.log.debug("%s online and has root" % host)
            else:
                non_root.append(host)
        if non_root:
            raise TestFailure(f"Found {len(non_root)} nodes with non-sudoer access",
                              hint=f"Nodes {', '.join(non_root)} do not have the appropriate sudoer access. "
                                   f"At these nodes, add a connection user to the sudoers group.")


def hardware_members_amount(cluster: KubernetesCluster, group_name: str) -> None:
    beauty_name = group_name.capitalize()
    if group_name == 'vip':
        beauty_name = 'VIP'
    if group_name == 'all':
        beauty_name = 'Total Node'

    hardware_minimal = static.GLOBALS['compatibility_map']['hardware']['minimal'][group_name]
    hardware_recommended = static.GLOBALS['compatibility_map']['hardware']['recommended'][group_name]

    with TestCase(cluster, '005',  'Hardware', '%ss Amount' % beauty_name,
                  minimal=hardware_minimal['amount'],
                  recommended=hardware_recommended['amount']) as tc:
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

        if amount < hardware_minimal['amount']:
            beauty_name = group_name
            if group_name == 'all':
                beauty_name = 'all node'
            raise TestFailure("Less than minimal. Detected %s item%s" % (amount, s),
                              hint="Increase the number of resources, so that the number of %ss in the cluster should not "
                                   "be less than %s." % (beauty_name, hardware_minimal['amount']))

        if amount < hardware_recommended['amount']:
            beauty_name = group_name
            if group_name == 'all':
                beauty_name = 'all node'
            raise TestWarn("Less than recommended. Detected %s item%s" % (amount, s),
                           hint="Increase the number of resources, so that the number of %ss in the cluster should not "
                                "be less than %s." % (beauty_name, hardware_minimal['amount']))

        tc.success("%s item%s" % (amount, s))


def hardware_cpu(cluster: KubernetesCluster, group_name: str) -> None:
    hardware_minimal = static.GLOBALS['compatibility_map']['hardware']['minimal'][group_name]
    hardware_recommended = static.GLOBALS['compatibility_map']['hardware']['recommended'][group_name]

    minimal_cpu = hardware_minimal['vcpu'] \
        if group_name == 'balancer' or cluster.nodes['all'].nodes_amount() > 1 \
        else static.GLOBALS['compatibility_map']['hardware']['minimal']['control-plane']['vcpu']
    with TestCase(cluster, '006',  'Hardware', 'VCPUs Amount - %ss' % group_name.capitalize(),
                  minimal=minimal_cpu,
                  recommended=hardware_recommended['vcpu']) as tc:
        sudo_nodes = cluster.make_group_from_roles([group_name]).get_sudo_nodes()
        if sudo_nodes.is_empty():
            return tc.success(results='Skipped')
        results = sudo_nodes.sudo("nproc --all")
        cluster.log.verbose(results)
        minimal_amount: Optional[int] = None
        for host, result in results.items():
            amount = int(result.stdout)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < minimal_cpu:
                cluster.log.error('%s node %s has insufficient VCPUs: expected %s, but %s found.'
                                  % (group_name.capitalize(), host, hardware_minimal['vcpu'], amount))
            elif amount < hardware_recommended['vcpu']:
                cluster.log.warning('%s node %s has less VCPUs than recommended: recommended %s, but %s found.'
                                    % (group_name.capitalize(), host, hardware_recommended['vcpu'], amount))
            else:
                cluster.log.debug('%s node %s has enough VCPUs: %s' % (group_name.capitalize(), host, amount))

        s = ''
        if minimal_amount != 1:
            s = 's'

        if minimal_amount < minimal_cpu:
            raise TestFailure("Less than minimal. Detected %s VCPU%s" % (minimal_amount, s),
                              hint="Increase the number of VCPUs in the node configuration to at least the minimum "
                                   "value: %s VCPUs." % hardware_minimal['vcpu'])
        if minimal_amount < hardware_recommended['vcpu']:
            raise TestWarn("Less than recommended. Detected %s VCPU%s" % (minimal_amount, s),
                           hint="Increase the number of VCPUs in the node configuration up to %s VCPUs."
                                % hardware_recommended['vcpu'])
        tc.success(results='%s VCPU%s' % (minimal_amount, s))


def hardware_ram(cluster: KubernetesCluster, group_name: str) -> None:
    hardware_minimal = static.GLOBALS['compatibility_map']['hardware']['minimal'][group_name]
    hardware_recommended = static.GLOBALS['compatibility_map']['hardware']['recommended'][group_name]

    with TestCase(cluster, '007',  'Hardware', 'RAM Amount - %ss' % group_name.capitalize(),
                  minimal=hardware_minimal['ram'],
                  recommended=hardware_recommended['ram']) as tc:
        sudo_nodes = cluster.make_group_from_roles([group_name]).get_sudo_nodes()
        if sudo_nodes.is_empty():
            return tc.success(results='Skipped')
        results = sudo_nodes.sudo("cat /proc/meminfo | awk '/DirectMap/ { print $2 }'")
        cluster.log.verbose(results)
        minimal_amount: Optional[int] = None
        for host, result in results.items():
            amount = math.floor(sum(map(int, result.stdout.strip().split("\n"))) / 1000000)
            if minimal_amount is None or minimal_amount > amount:
                minimal_amount = amount
            if amount < hardware_minimal['ram']:
                cluster.log.error('%s node %s has insufficient RAM: expected %sGB, but %sGB found.'
                                  % (group_name.capitalize(), host, hardware_minimal['ram'], amount))
            elif amount < hardware_recommended['ram']:
                cluster.log.warning('%s node %s has less RAM than recommended: recommended %sGB, but %sGB found.'
                                    % (group_name.capitalize(), host, hardware_recommended['ram'], amount))
            else:
                cluster.log.debug('%s node %s has enough RAM: %sGB' % (group_name.capitalize(), host, amount))
        if minimal_amount < hardware_minimal['ram']:
            raise TestFailure("Less than minimal. Detected %sGB" % minimal_amount,
                              hint="Increase the number of RAM in the node configuration to at least the minimum "
                                   "value: %sGB." % hardware_minimal['ram'])
        if minimal_amount < hardware_recommended['ram']:
            raise TestWarn("Less than recommended. Detected %sGB" % minimal_amount,
                           hint="Increase the number of RAM in the node configuration up to %s GB."
                                % hardware_recommended['ram'])
        tc.success(results='%sGB' % minimal_amount)


def system_distributive(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '008', 'System', 'Distributive') as tc:
        supported_distributives = cluster.globals['compatibility_map']['distributives'].keys()

        cluster.log.debug(system.fetch_os_versions(cluster))

        detected_unsupported_os = []
        detected_supported_os = []
        detected_unsupported_version = []
        supported_versions = []
        for address, context_data in cluster.nodes_context.items():
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
            elif context_data['os']['family'] != '<undefined>':
                detected_supported_os.append(detected_os)
                cluster.log.debug('Host %s running \"%s\"' % (address, detected_os))

        detected_supported_os = list(set(detected_supported_os))
        detected_unsupported_os = list(set(detected_unsupported_os))
        detected_unsupported_version = list(set(detected_unsupported_version))
        supported_versions = list(set(supported_versions))

        if detected_unsupported_os:
            raise TestFailure("Unsupported OS: %s" % ", ".join(detected_unsupported_os),
                              hint="Reinstall the OS on the host to one of the supported: %s"
                                   % ", ".join(supported_distributives))

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

        if not detected_supported_os:
            return tc.success(results="Skipped")

        tc.success(results=", ".join(detected_supported_os))


def check_kernel_version(cluster: KubernetesCluster) -> None:
    """
    This method compares the linux kernel version with the bad version
    """
    with TestCase(cluster, '015', "Software", "Kernel version") as tc:
        bad_results = {}
        unstable_kernel_ubuntu: List[str] = cluster.globals['compatibility_map']['distributives']['ubuntu'][0] \
            .get('unstable_kernel')
        unstable_kernel_centos: List[str] = []
        group = cluster.nodes['all'].get_accessible_nodes()
        result_group = group.run('uname -r')
        for host, results in result_group.items():
            os_name = cluster.nodes_context[host]['os']['name']
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
        check_resolv_conf(cluster)
        broken: List[str] = []
        warnings = nodes_require_python(cluster)

        problem_handlers: Dict[str, List[str]] = {}

        def resolve_problem_handler(host: str) -> List[str]:
            handler = problem_handlers.get(host)
            if handler is None:
                resolv_conf_actual = cluster.nodes_context[host]['resolv_conf_is_actual']
                if not resolv_conf_actual:
                    warnings.append(f"resolv.conf is not installed for node {host}: "
                                    f"Thirdparties can be unavailable. You can install resolv.conf using task "
                                    f"`install --tasks prepare.dns.resolv_conf`")
                    handler = warnings
                else:
                    handler = broken

                problem_handlers[host] = handler

            return handler

        # Load script for checking sources
        all_group = get_python_group(cluster, True)
        check_script = utils.read_internal("resources/scripts/check_url_availability.py")
        random_temp_path = utils.get_remote_tmp_path(ext='py')
        all_group.put(io.StringIO(check_script), random_temp_path)

        for destination, config in cluster.inventory['services'].get('thirdparties', {}).items():
            # Check if curl
            if config['source'][:4] != 'http' or '://' not in config['source'][4:8]:
                continue
            # Check with script
            common_group = thirdparties.get_install_group(cluster, config).intersection_group(all_group)
            for node in common_group.get_ordered_members_list():
                host = node.get_host()
                python_executable = cluster.nodes_context[host]['python']['executable']
                res = node.run("%s %s %s %s"
                               % (python_executable, random_temp_path, config['source'],
                                  cluster.inventory['globals']['timeout_download']),
                               pty=True, warn=True)
                problem_handler = resolve_problem_handler(host)
                if res.is_any_failed():
                    problem_handler.append(f"{host}, {destination}: {res[host].stdout}")

        # Remove file
        rm_command = "rm %s" % random_temp_path
        all_group.run(rm_command)

        if broken:
            raise TestFailure('Required thirdparties are unavailable', hint=yaml.safe_dump(broken))
        if warnings:
            raise TestWarn("Can't detect python version for some nodes",
                           hint='\n'.join(warnings))
        tc.success('All thirdparties are available')


def check_resolv_conf(cluster: KubernetesCluster) -> None:
    nodes_context = cluster.nodes_context
    hosts = [host for host, node_context in nodes_context.items() if 'resolv_conf_is_actual' not in node_context]

    if cluster.inventory["services"].get("resolv.conf") is None:
        for host in hosts:
            nodes_context[host]["resolv_conf_is_actual"] = True
    else:
        group = cluster.make_group(hosts).get_accessible_nodes()
        # Create temp resolv.conf file
        resolv_conf_buffer = system.get_resolv_conf_buffer(cluster.inventory["services"].get("resolv.conf"))
        random_resolv_conf_path = utils.get_remote_tmp_path(ext='conf')
        group.put(resolv_conf_buffer, random_resolv_conf_path)

        # Compare with existed resolv.conf
        results = group.run(
            '[ -f /etc/resolv.conf ] && '
            'cmp --silent /etc/resolv.conf %s' % random_resolv_conf_path,
            warn=True)

        for host in hosts:
            node_context = nodes_context[host]
            node_context["resolv_conf_is_actual"] = '<undefined>'
            if host not in results:
                continue

            node_context["resolv_conf_is_actual"] = results[host].ok
        # Remove temp resolv.conf file
        group.run("rm %s" % random_resolv_conf_path)


def check_package_repositories(cluster: KubernetesCluster) -> None:
    nodes_context = cluster.nodes_context
    hosts = [host for host, node_context in nodes_context.items() if 'package_repos_are_actual' not in node_context]

    repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
    if repositories is None:
        for host in hosts:
            nodes_context[host]["package_repos_are_actual"] = True
    else:
        group = cluster.make_group(hosts).get_sudo_nodes()
        random_repos_conf_path = utils.get_remote_tmp_path(ext='repo')
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

        for host in hosts:
            node_context = nodes_context[host]
            node_context["package_repos_are_actual"] = '<undefined>'
            if host not in collector.result:
                continue

            node_context["package_repos_are_actual"] = collector.result[host].ok

        # Remove temp .repo file
        group.sudo("rm %s" % random_repos_conf_path)


def check_access_to_package_repositories(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '013', 'Software', 'Package Repositories') as tc:
        detect_preinstalled_python(cluster)
        check_resolv_conf(cluster)
        broken = []
        warnings = nodes_require_python(cluster)

        # Collect repository urls
        # TODO: think about better parsing
        repository_urls: List[str] = []
        repositories = cluster.inventory['services']['packages']['package_manager'].get("repositories")
        if cluster.get_os_family() not in ['debian', 'rhel', 'rhel8', 'rhel9']:
            # Skip check in case of multiply or unknown OS
            raise TestWarn("Can't check package repositories on multiple or unknown OS")
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
        all_group = get_python_group(cluster, True)
        check_script = utils.read_internal("resources/scripts/check_url_availability.py")
        random_temp_path = utils.get_remote_tmp_path(ext='py')
        all_group.put(io.StringIO(check_script), random_temp_path)

        if repository_urls:
            collector = CollectorCallback(cluster)
            with all_group.new_executor() as exe:
                for node in exe.group.get_ordered_members_list():
                    host = node.get_host()
                    # Check with script
                    python_executable = cluster.nodes_context[host]['python']['executable']
                    for repo_url in repository_urls:
                        node.run('%s %s %s %s'
                                 % (python_executable, random_temp_path, repo_url,
                                    cluster.inventory['globals']['timeout_download']),
                                 pty=True, warn=True, callback=collector)

            for host, url_results in collector.results.items():
                # Check if resolv.conf is actual
                resolv_conf_actual = cluster.nodes_context[host]['resolv_conf_is_actual']
                if not resolv_conf_actual:
                    warnings.append(f"resolv.conf is not installed for node {host}: "
                                    f"Package repositories can be unavailable. You can install resolv.conf using task "
                                    f"`install --tasks prepare.dns.resolv_conf`")
                    problem_handler = warnings
                else:
                    problem_handler = broken
                for i, result in enumerate(url_results):
                    if result.failed:
                        problem_handler.append(f"{host}, {repository_urls[i]}: {result.stdout}")

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
        group = cluster.nodes['all'].get_sudo_nodes()
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
            package_repos_are_actual = cluster.nodes_context[host]["package_repos_are_actual"]
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

    nodes_context = cluster.nodes_context
    hosts_unknown_python = [host for host, node_context in nodes_context.items() if 'python' not in node_context]
    group_unknown_python = cluster.make_group(hosts_unknown_python)
    if group_unknown_python.is_empty():
        return

    detected_python = group_unknown_python.get_accessible_nodes().run(
        rf'for i in $(whereis -b python && whereis -b python3 ); do '
        rf'if [[ -f "$i" ]] && [[ $($i --version 2>&1 | head -n 1) =~ {bash_version_pattern} ]]; then '
        rf'echo "$i"; $i --version 2>&1; break; '
        rf'fi; done')

    for host in hosts_unknown_python:
        node_context = nodes_context[host]
        node_context["python"] = '<undefined>'
        if host not in detected_python:
            continue

        identity = detected_python[host].stdout.strip()
        if not identity:
            node_context["python"] = "Not installed"
        else:
            executable, version = tuple(identity.splitlines())
            version = cast(Match[str], re.match(python_version_pattern, version)).group(1)
            node_context["python"] = {
                "executable": executable,
                "major_version": version
            }


@contextmanager
def suspend_firewalld(cluster: KubernetesCluster) -> Iterator[None]:
    group = cluster.nodes["all"].get_sudo_nodes()
    firewalld_statuses = system.fetch_firewalld_status(group)
    stop_firewalld_group = firewalld_statuses.get_nodes_group_where_value_in_stdout("active (running)")

    try:
        system.stop_service(stop_firewalld_group, "firewalld")
        yield
    finally:
        system.start_service(stop_firewalld_group, "firewalld", warn=True)


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
    try:
        # Create alias from the node network interface for the subnet on every node
        with group.new_executor() as exe:
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                node.sudo(f"ip a add {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}")

        yield
    finally:
        # Remove the created aliases from network interfaces
        with group.new_executor() as exe:
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                node.sudo(f"ip a del {host_to_ip[host]}/{prefix} dev {host_to_inf[host]}",
                          warn=True)


@contextmanager
def assign_random_ips(cluster: KubernetesCluster, group: NodeGroup, host_to_inf: Dict[str, str], subnet: str) \
        -> Iterator[Dict[str, str]]:
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
    for host in cluster.nodes['all'].get_accessible_nodes().get_hosts():
        inf = cluster.nodes_context[host]['active_interface']
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
    group = cluster.make_group_from_roles(['control-plane', 'worker']).get_sudo_nodes()\
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

    python_executable = cluster.nodes_context[node.get_host()]['python']['executable']
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
    node.run(cmd, timeout=timeout, pty=True)


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
               "echo \"$PORT in use\" ; " \
               "exit 0; " \
           "elif [[ $DATA == \"Listen\" ]]; then " \
               "exit 0; " \
           "fi; " \
           "echo -n \"$DATA\" ; " \
           "exit 1"


def get_stop_listener_cmd(port_listener: str) -> str:
    identify_pid = f"ps aux | grep \" {port_listener} ${{port}}$\" " \
                   f"| grep -v grep | grep -v nohup | awk '{{print $2}}'"
    return f"port=%s;pid=$({identify_pid}) " \
           "&& if [ ! -z $pid ]; then sudo kill -9 $pid; echo \"killed pid $pid for port $port\"; fi"


def install_client(group: DeferredGroup, proto: str, mtu: int, timeout: int) -> str:
    check_script = utils.read_internal('resources/scripts/simple_port_client.py')
    udp_client = utils.get_remote_tmp_path(ext='py')
    for node in group.get_ordered_members_list():
        rendered_script = Template(check_script).render({
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

    group = get_python_group(cluster, True).get_accessible_nodes().new_defer()
    timeout = static.GLOBALS['connection']['defaults']['timeout']
    port_client = install_client(group, proto, mtu, timeout)

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
        python_spec: Union[dict, str] = cluster.nodes_context[node['connect_to']]['python']
        return has_python == (python_spec not in ("Not installed", '<undefined>'))

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
    port_listener = utils.get_remote_tmp_path(ext='py')

    listened_ports: Dict[str, List[Tuple[str, bool]]] = {}
    try:
        collector = CollectorCallback(cluster)
        with group.new_executor() as exe:
            # Run processes that listen TCP or UDP ports
            for node in exe.group.get_ordered_members_list():
                host = node.get_host()
                bind_address = host_to_ip[host]
                ip_version = ipaddress.ip_address(bind_address).version
                rendered_script = Template(check_script).render({
                    'proto': proto,
                    'address': bind_address,
                    'ip_version': ip_version,
                    'mtu': mtu,
                })
                node.put(io.StringIO(rendered_script), port_listener)

                python_executable = cluster.nodes_context[host]['python']['executable']
                port_start_listener_cmd = get_start_listener_cmd(python_executable, port_listener)
                for port in host_ports[host]:
                    node.sudo(f"echo 'port: {port}' && ( {port_start_listener_cmd % port} )",
                              callback=collector, pty=True)

        port_in_use_ptrn = re.compile(r'^port: (\d+)\n((\1) in use\n)?$', re.M)
        for host, results in collector.results.items():
            ports_in_use = []
            for result in results:
                matcher = port_in_use_ptrn.match(result.stdout)
                if matcher is None:
                    raise GroupResultException(collector.result)
                elif matcher.group(2) is not None:
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

        group = get_python_group(cluster, True).get_sudo_nodes()

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

        keepalived_group = keepalived_group.get_sudo_nodes()\
            .intersection_group(get_python_group(cluster, True))
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
                    get_python_group(cluster, True).get_sudo_nodes().exclude_group(node)\
                        .sudo(f'ip neigh flush {ip}')

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


def ipip_connectivity(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '017', 'Network', 'IP in IP Encapsulation', default_results='Connected'), \
            suspend_firewalld(cluster):

        skipped_msgs = []

        # Check encapsulation for 'Calico' CNI
        if not cluster.inventory['plugins']['calico']['install']:
            skipped_msgs.append("Calico is not set as CNI for the cluster")
            raise TestWarn("Check cannot be completed", hint='\n'.join(skipped_msgs))

        # Check encapsulation for clusters with two or more nodes
        group = cluster.make_group_from_roles(['control-plane', 'worker']).get_sudo_nodes()
        if group.nodes_amount() == 1:
            skipped_msgs.append("Too few nodes, check is skipped")
            raise TestWarn("Check cannot be completed", hint='\n'.join(skipped_msgs))

        enc_type = cluster.inventory['plugins']['calico']['mode']
        if enc_type == "ipip":
            # Check if IPv6 addresses are used
            connect_to_ip = group.get_ordered_members_configs_list()[0]['internal_address']
            if utils.isipv(connect_to_ip, [6]):
                skipped_msgs.append("IPv6 is not supported by IP in IP encapsulation")
                raise TestWarn("Check cannot be completed", hint='\n'.join(skipped_msgs))
            ip = cluster.inventory['services']['kubeadm']['networking']['podSubnet'].split('/')[0]
            if utils.isipv(ip, [6]):
                skipped_msgs.append("IPv6 is not supported by IP in IP encapsulation")
                raise TestWarn("Check cannot be completed", hint='\n'.join(skipped_msgs))
            failed_nodes = check_ipip_tunnel(group)
        else:
            skipped_msgs.append("Encapsulation IPIP is disabled")
            raise TestWarn("Check cannot be completed", hint='\n'.join(skipped_msgs))

        if failed_nodes:
            raise TestFailure(f"Check firewall settings for all nodes in the cluster, "
                              "IP in IP traffic is not allowed between nodes.", hint='\n'.join(failed_nodes))

        if group.nodes_amount() == 2:
            skipped_msgs.append("Change nodes order in 'cluster.yaml' and run the check "
                                "10 minutes later")
            raise TestWarn("Check has been succeded for the second node but cannot be completed for "
                           "the first node", hint='\n'.join(skipped_msgs))

def check_ipip_tunnel(group: NodeGroup) -> Set[str]:

    group_to_rollback = group
    cluster = group.cluster

    # Copy binaries to the nodes
    random_sport = str(random.randint(50000, 65535))
    random_dport = str(random.randint(50000, 65535))
    failed_nodes: Set[str] = set()
    recv_cmd: Dict[str, str] = {}
    trns_cmd: Dict[str, str] = {}

    binary_check_path = utils.get_internal_resource_path('./resources/scripts/ipip_check.gz')
    ipip_check = '/tmp/kubemarine_ipip_check'
    ipip_check_pid = utils.get_remote_tmp_path()
    # Random message
    random.seed()
    msg = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
    # Random IP from class E
    int_ip = random.randint(4026531841, 4294967294)
    fake_addr = str(ipaddress.IPv4Address(int_ip))
    # That is used as number of packets for transmitter
    timeout = int(cluster.inventory['globals']['timeout_download'])
    nodes_list = group.get_ordered_members_configs_list()
    # The ring circuit is used for the procedure. Each node in the ring transmit IPIP packets to the next node in the ring
    # and receive IPIP packets from the previous node of the ring.
    # That makes check more robast to some IP filters implementation.
    recv_neighbor_node: Dict[str, str] = {}
    trns_neighbor_host = ""
    if len(nodes_list) > 2:
        node_number = 0
        for node in nodes_list:
            host = node['internal_address']
            if node_number < len(nodes_list) - 1:
                recv_neighbor_node[nodes_list[node_number + 1]['name']] = node['name']
                trns_neighbor_host = nodes_list[node_number + 1]['internal_address']
            else:
                recv_neighbor_node[nodes_list[0]['name']] = node['name']
                trns_neighbor_host = nodes_list[0]['internal_address']
            # Transmitter start command
            # Transmitter starts first and sends IPIP packets every 1 second until the timeout comes or
            # the process is killed by terminating command
            trns_cmd[host] = f"nohup {ipip_check} -mode client -src {host} -int {fake_addr} " \
                             f"-ext {trns_neighbor_host} -sport {random_sport} -dport {random_dport} " \
                             f"-msg {msg} -timeout {timeout} > /dev/null 2>&1 & echo $! >> {ipip_check_pid}"
            # Receiver start command
            # Receiver starts after the transmitter and try to get IPIP packets within 3 seconds from neighbor node
            recv_cmd[host] = f"{ipip_check} -mode server -ext {host} -int {fake_addr} -sport {random_sport}" \
                             f" -dport {random_dport} -msg {msg} -timeout 3 2> /dev/null"
            node_number += 1
    else:
        # Two nodes have only one transmitter and only one receiver
        host = nodes_list[0]['internal_address']
        recv_neighbor_node[nodes_list[1]['name']] = nodes_list[0]['name']
        trns_neighbor_host = nodes_list[1]['internal_address']
        trns_cmd[host] = f"nohup {ipip_check} -mode client -src {host} -int {fake_addr} " \
                         f"-ext {trns_neighbor_host} -sport {random_sport} -dport {random_dport} " \
                         f"-msg {msg} -timeout {timeout} > /dev/null 2>&1 & echo $! >> {ipip_check_pid}"
        host = nodes_list[1]['internal_address']
        recv_cmd[host] = f"{ipip_check} -mode server -ext {host} -int {fake_addr} -sport {random_sport} " \
                         f"-dport {random_dport} -msg {msg} -timeout 3 2> /dev/null"

    try:
        collector = CollectorCallback(group.cluster)
        cluster.log.debug("Copy binaries to the nodes")
        group.put(binary_check_path, f"{ipip_check}.gz", compare_hashes=True)
        group.run(f"gzip -d -k -f {ipip_check}.gz")
        group.run(f"chmod +x {ipip_check}")
        # Run transmitters if it's applicable for node
        cluster.log.debug("Run transmitters")
        with group.new_executor() as exe:
            for node_exe in exe.group.get_ordered_members_list():
                host_int = node_exe.get_config()['internal_address']
                if trns_cmd.get(host_int, ""):
                    node_exe.sudo(f"{trns_cmd[host_int]}")
        # Run receivers and get results if it's applicable for node
        cluster.log.debug("Run receivers")
        with group.new_executor() as exe:
            for node_exe in exe.group.get_ordered_members_list():
                host_int = node_exe.get_config()['internal_address']
                if recv_cmd.get(host_int, ""):
                    node_exe.sudo(f"{recv_cmd[host_int]}", warn=True, pty=True, callback=collector)

        for host, item in collector.result.items():
            node_name = cluster.get_node_name(host)
            item_list: Set[str] = set()
            if len(item.stdout) > 0:
                for log_item in item.stdout.split("\n")[:-1]:
                    item_list.add(log_item)
            # Check if the neighbor IP is in logs
            trns_node = group.get_member_by_name(recv_neighbor_node[node_name]).get_config()
            if trns_node['internal_address'] not in item_list:
                failed_nodes.add(f"{trns_node['name']} -> {node_name}")

        return failed_nodes
    finally:
        # Delete binaries ang logs
        cluster.log.debug("Delete binaries")
        with group_to_rollback.new_executor() as exe:
            for node_exe in exe.group.get_ordered_members_list():
                node_exe.sudo(
                    f"pkill -9 -P $(cat {ipip_check_pid} | xargs | tr ' ' ','); "
                    f"sudo rm -f {ipip_check_pid}", warn=True)


def fs_mount_options(cluster: KubernetesCluster) -> None:
    with TestCase(cluster, '018', 'System', 'Filesystem mount options'):

        failed_nodes: Set[str] = set()
        # Only Kubernetes nodes should be checked
        group = cluster.make_group_from_roles(['control-plane', 'worker']).get_sudo_nodes()
        # Containerd root
        cri_root = cluster.inventory['services']['cri']['containerdConfig'].get('root', '/var/lib/containerd')

        cluster.log.debug("Mount options check")
        # Check the mount options for filesystem where containerd root is located.
        # If containerd root doesn't exist the script check the parent directory and so forth.
        # At the end of the script 'findmnt' return the filesytem mount point, device,
        # and mount options for nearest parent directory of CRI root.
        # 'findmnt' perform the recursive search of mount point for filesystem
        # from the given path to the root, that's exactly what we need.
        cmd = f"CRI_PATH={cri_root}; while [ ! -d \"${{CRI_PATH}}\" ]; do CRI_PATH=$(dirname \"${{CRI_PATH}}\"); " \
              f"done; findmnt -T \"${{CRI_PATH}}\" | grep 'nosuid'"
        results = group.run(f"{cmd}", warn=True)

        # Check output and create result message
        for host, item in results.items():
            node_name = cluster.get_node_name(host)
            if len(item.stdout) > 0:
                failed_nodes.add(f"{node_name}")

        if failed_nodes:
            raise TestFailure(f"The 'nosuid' mount option affects container functionality. "
                              f"Please change mount options for filesystem where CRI "
                              f"root is located on the following nodes. CRI root path is '{cri_root}'",
                              hint='\n'.join(failed_nodes))


def make_reports(context: dict, testsuite: TestSuite) -> None:
    if not context['execution_arguments'].get('disable_csv_report', False):
        testsuite.save_csv(context['execution_arguments']['csv_report'], context['execution_arguments']['csv_report_delimiter'])
    if not context['execution_arguments'].get('disable_html_report', False):
        testsuite.save_html(context['execution_arguments']['html_report'], context['initial_procedure'].upper())


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
        'ports_connectivity': ports_connectivity,
        'vips_connectivity': vips_connectivity,
        'ipip_connectivity': ipip_connectivity,
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
        },
    },
    'system': {
        'distributive': system_distributive,
        'fs_mount_options': fs_mount_options
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


class IaasAction(flow.TasksAction):
    def __init__(self) -> None:
        super().__init__('check iaas', tasks)


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
    context['result'].append('testsuite')

    return context


def main(cli_arguments: List[str] = None) -> TestSuite:
    context = create_context(cli_arguments)
    flow_ = flow.ActionsFlow([IaasAction()])
    result = flow_.run_flow(context, print_summary=False)

    testsuite: TestSuite = result.context['testsuite']

    # Final summary should be printed only to stdout with custom formatting
    # If test results are required for parsing, they can be found in the test results files
    testsuite.print_final_summary()
    testsuite.print_final_status(result.logger)
    make_reports(context, testsuite)
    return testsuite


if __name__ == '__main__':
    testsuite = main()
    if testsuite.is_any_test_failed():
        sys.exit(1)
