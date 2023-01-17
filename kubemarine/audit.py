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
from kubemarine.core.annotations import restrict_multi_os_group
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult


def verify_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    for host in cluster.nodes['all'].get_hosts():
        package_name = cluster.get_package_association_for_node(host, 'audit', 'package_name')
        if isinstance(package_name, str):
            package_name = [package_name]

        if len(package_name) != 1:
            raise Exception(f'Audit can not be installed with not single associated package {package_name} '
                            f'for node {host!r}')

    return inventory


@restrict_multi_os_group
def install(group: NodeGroup) -> str or None:
    """
    Automatically installs and enables the audit service for the specified nodes
    :param group: Nodes group on which audit installation should be performed
    :return: String with installation output from nodes or None, when audit installation was skipped
    """
    cluster = group.cluster
    log = cluster.log

    if group.get_nodes_os() in ['rhel', 'rhel8']:
        log.debug('Auditd installation is not required on RHEL nodes')
        return

    log.verbose('Searching for already installed auditd package...')
    any_host = group.get_first_member().get_host()
    debian_package_name = cluster.get_package_association_for_node(any_host, 'audit', 'package_name')
    if isinstance(debian_package_name, list):
        debian_package_name = debian_package_name[0]

    audit_installed_results = packages.detect_installed_package_version(group, debian_package_name)
    log.verbose(audit_installed_results)

    # Reduce nodes amount for installation
    group = audit_installed_results.get_nodes_group_where_value_in_stderr("no packages found matching")

    if group.nodes_amount() == 0:
        log.debug('Auditd is already installed on all nodes')
        return
    else:
        log.debug('Auditd package is not installed, installing...')

    with RemoteExecutor(cluster) as exe:
        packages.install(group, include=debian_package_name)
        enable(group)

    return exe.get_last_results_str()


@restrict_multi_os_group
def enable(group: NodeGroup) -> NodeGroupResult:
    """
    Enables and optionally starts the audit service for the specified nodes
    :param group: Nodes group, where audit service should be enabled
    :param now: Flag indicating that the audit service should be started immediately
    :return: NodeGroupResult of enabling output from nodes
    """
    cluster = group.cluster

    any_host = group.get_first_member().get_host()
    service_name = cluster.get_package_association_for_node(any_host, 'audit', 'service_name')
    return system.enable_service(group, name=service_name)


@restrict_multi_os_group
def restart(group: NodeGroup) -> NodeGroupResult:
    """
    Restarts the audit service for the specified nodes
    :param group: Nodes group, where audit service should be restarted
    :return: Service restart NodeGroupResult
    """
    cluster = group.cluster

    any_host = group.get_first_member().get_host()
    service_name = cluster.get_package_association_for_node(any_host, 'audit', 'service_name')
    return group.sudo(f'service {service_name} restart')


@restrict_multi_os_group
def apply_audit_rules(group: NodeGroup) -> NodeGroupResult:
    """
    Generates and applies audit rules to the group
    :param group: Nodes group, where audit service should be configured
    :param now: Flag indicating that the audit service should be restarted immediately
    :return: Service restart result or nothing if audit rules are non exists, or restart is not required
    """
    cluster = group.cluster
    log = cluster.log

    log.debug('Applying audit rules...')
    rules_content = " \n".join(group.cluster.inventory['services']['audit']['rules'])
    utils.dump_file(group.cluster, rules_content, 'audit.rules')

    any_host = group.get_first_member().get_host()
    rules_config_location = cluster.get_package_association_for_node(any_host, 'audit', 'config_location')
    group.put(io.StringIO(rules_content), rules_config_location,
              sudo=True, backup=True)

    return restart(group)
