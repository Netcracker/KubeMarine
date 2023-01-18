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

from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    for host in cluster.nodes['all'].get_final_nodes().get_hosts():
        package_name = cluster.get_package_association_for_node(host, 'audit', 'package_name')
        if isinstance(package_name, str):
            package_name = [package_name]

        if len(package_name) != 1:
            os_family = cluster.get_os_family_for_node(host)
            raise Exception(f'Audit has multiple associated packages {package_name} for OS {os_family!r} '
                            f'that is currently not supported')

    return inventory


def install(group: NodeGroup) -> str or None:
    """
    Automatically installs and enables the audit service for the specified nodes
    :param group: Nodes group on which audit installation should be performed
    :return: String with installation output from nodes or None, when audit installation was skipped
    """
    cluster = group.cluster
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
        return
    else:
        log.debug(f'Auditd package is not installed on {not_installed_hosts}, installing...')

    with RemoteExecutor(cluster) as exe:
        for host in not_installed_hosts:
            the_node = cluster.make_group([host])

            package_name = cluster.get_package_association_for_node(host, 'audit', 'package_name')
            packages.install(the_node, include=package_name)

            service_name = cluster.get_package_association_for_node(host, 'audit', 'service_name')
            system.enable_service(the_node, name=service_name)

    return exe.get_last_results_str()


def apply_audit_rules(group: NodeGroup) -> NodeGroupResult:
    """
    Generates and applies audit rules to the group
    :param group: Nodes group, where audit service should be configured
    :return: Service restart result or nothing if audit rules are non exists, or restart is not required
    """
    cluster = group.cluster
    log = cluster.log

    log.debug('Applying audit rules...')
    rules_content = " \n".join(cluster.inventory['services']['audit']['rules'])
    utils.dump_file(cluster, rules_content, 'audit.rules')

    restart_tokens = []
    with RemoteExecutor(cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            the_node: NodeGroup = node['connection']
            host: str = node['connect_to']

            rules_config_location = cluster.get_package_association_for_node(host, 'audit', 'config_location')
            the_node.put(io.StringIO(rules_content), rules_config_location,
                         sudo=True, backup=True)

            service_name = cluster.get_package_association_for_node(host, 'audit', 'service_name')
            restart_tokens.append(the_node.sudo(f'service {service_name} restart'))

    return exe.get_merged_nodegroup_results(restart_tokens)
