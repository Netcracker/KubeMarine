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

"""
This module works with audit on remote nodes.
Using this module you can install, enable audit and configure audit rules.
"""

import io
import shlex
from typing import Optional, Tuple, List, Set

from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    for node in cluster.nodes['all'].get_final_nodes().get_ordered_members_list():
        if node.get_nodes_os() in ('unknown', 'unsupported'):
            continue
        host = node.get_host()
        package_name = cluster.get_package_association_for_node(host, 'audit', 'package_name')
        if isinstance(package_name, str):
            package_name = [package_name]

        if len(package_name) != 1:
            os_family = cluster.get_os_family_for_node(host)
            raise Exception(f'Audit has multiple associated packages {package_name} for OS {os_family!r} '
                            f'that is currently not supported')

    return inventory


def install(group: NodeGroup) -> Optional[RunnersGroupResult]:
    """
    Automatically installs and enables the audit service for the specified nodes
    :param group: Nodes group on which audit installation should be performed
    :return: String with installation output from nodes or None, when audit installation was skipped
    """
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    log.verbose('Searching for already installed auditd package...')

    # Reduce nodes amount for installation
    hosts_to_packages = packages.get_association_hosts_to_packages(group, cluster.inventory, 'audit')

    not_installed_hosts = []
    audit_installed_results = packages.detect_installed_packages_version_hosts(cluster, hosts_to_packages)
    for detected_audit_versions in audit_installed_results.values():
        for detected_version, hosts in detected_audit_versions.items():
            log.verbose(f'{detected_version}: {hosts}')
            if 'not installed' in detected_version:
                not_installed_hosts.extend(hosts)

    if not not_installed_hosts:
        log.debug('Auditd is already installed on all nodes')
        return None
    else:
        log.debug(f'Auditd package is not installed on {not_installed_hosts}, installing...')

    collector = CollectorCallback(cluster)
    with cluster.make_group(not_installed_hosts).new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            package_name = cluster.get_package_association_for_node(node.get_host(), 'audit', 'package_name')
            packages.install(node, include=package_name, callback=collector)

            service_name = cluster.get_package_association_for_node(node.get_host(), 'audit', 'service_name')
            system.enable_service(node, name=service_name, callback=collector)

    return collector.result


def make_config(cluster: KubernetesCluster) -> str:
    return " \n".join(cluster.inventory['services']['audit']['rules'])


def apply_audit_rules(group: NodeGroup) -> RunnersGroupResult:
    """
    Generates and applies audit rules to the group
    :param group: Nodes group, where audit service should be configured
    :return: Service restart result or nothing if audit rules are non exists, or restart is not required
    """
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    rules_valid, auditctl_results = audit_rules_valid(group)
    if rules_valid:
        log.debug('Auditd rules are already actual on all nodes')
        return auditctl_results

    log.debug('Applying audit rules...')
    rules_content = make_config(cluster)
    utils.dump_file(cluster, rules_content, 'audit.rules')

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            host = node.get_host()

            rules_config_location = cluster.get_package_association_for_node(host, 'audit', 'config_location')
            node.put(io.StringIO(rules_content), rules_config_location, sudo=True, backup=True)

            service_name = cluster.get_package_association_for_node(host, 'audit', 'service_name')
            node.sudo(f'service {service_name} restart', callback=collector)

    _, auditctl_results = audit_rules_valid(group, silent=True)
    return auditctl_results


def audit_rules_valid(group: NodeGroup, silent: bool = False) -> Tuple[bool, RunnersGroupResult]:
    cluster: KubernetesCluster = group.cluster
    logger = cluster.log

    rules_content = make_config(cluster)

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            executable = cluster.get_package_association_for_node(node.get_host(), 'audit', 'executable_name')
            node.sudo(f'{executable} -l', callback=collector)

    verify_results = collector.result
    rules_valid = True
    for host, result in verify_results.items():
        tokens: List[Set[str]] = [set(shlex.split(line)) for line in result.stdout.rstrip('\n').split('\n')]
        for rule in rules_content.split('\n'):
            if not any(set(shlex.split(rule)).issubset(token) for token in tokens):
                if not silent:
                    logger.debug(f'Audit rule {rule!r} is not found at {host}')
                rules_valid = False

    return rules_valid, verify_results
