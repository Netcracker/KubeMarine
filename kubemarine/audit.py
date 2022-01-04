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
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup, NodeGroupResult


def is_audit_rules_defined(inventory) -> bool:
    """
    Checks for the presence of the specified audit rules in the inventory
    :param inventory: Cluster inventory, where the rules will be checked
    :return: Boolean
    """
    rules = inventory['services'].get('audit', {}).get('rules')
    return rules is not None


@restrict_multi_os_group
def install(group: NodeGroup, enable_service: bool = True, force: bool = False) -> NodeGroupResult or None:
    """
    Automatically installs and enables the audit service for the specified nodes
    :param group: Nodes group on which audit installation should be performed
    :param enable_service: Flag, automatically enables the service after installation
    :param force: A flag that causes a forced installation even on centos nodes and nodes where the audit is already
    installed
    :return: String with installation output from nodes or None, when audit installation was skipped
    """
    cluster = group.cluster
    log = cluster.log

    if not is_audit_rules_defined(cluster.inventory):
        log.debug('Skipped - no audit rules in inventory')
        return

    # This method handles cluster with multiple os, exceptions should be suppressed
    if not force and group.get_nodes_os(suppress_exceptions=True) in ['rhel', 'rhel8']:
        log.debug('Auditd installation is not required on RHEL nodes')
        return

    install_group = group

    if not force:
        log.verbose('Searching for already installed auditd package...')
        debian_group = group.get_subgroup_with_os('debian')
        debian_package_name = cluster.get_package_association_str_for_group(debian_group, 'audit', 'package_name')
        if isinstance(debian_package_name, list):
            raise Exception(f'Audit can not be installed, because nodes already contains different package versions: '
                            f'{str(debian_package_name)}')
        audit_installed_results = packages.detect_installed_package_version(debian_group, debian_package_name)
        log.verbose(audit_installed_results)

        # Reduce nodes amount for installation
        install_group = audit_installed_results.get_nodes_group_where_value_in_stderr("no packages found matching")

        if install_group.nodes_amount() == 0:
            log.debug('Auditd is already installed on all nodes')
            return
        else:
            log.debug('Auditd package is not installed, installing...')

    package_name = cluster.get_package_association_str_for_group(install_group, 'audit', 'package_name')

    with RemoteExecutor(cluster) as exe:
        packages.install(install_group, include=package_name)
        if enable_service:
            enable(install_group)

    return exe.get_last_results_str()


@restrict_multi_os_group
def enable(group: NodeGroup, now: bool = True) -> NodeGroupResult:
    """
    Enables and optionally starts the audit service for the specified nodes
    :param group: Nodes group, where audit service should be enabled
    :param now: Flag indicating that the audit service should be started immediately
    :return: NodeGroupResult of enabling output from nodes
    """
    cluster = group.cluster

    service_name = cluster.get_package_association_str_for_group(group, 'audit', 'service_name')
    return system.enable_service(group, name=service_name, now=now)


@restrict_multi_os_group
def restart(group: NodeGroup) -> NodeGroupResult:
    """
    Restarts the audit service for the specified nodes
    :param group: Nodes group, where audit service should be restarted
    :return: Service restart NodeGroupResult
    """
    cluster = group.cluster

    service_name = cluster.get_package_association_str_for_group(group, 'audit', 'service_name')
    return group.sudo(f'service {service_name} restart')


@restrict_multi_os_group
def apply_audit_rules(group: NodeGroup, now: bool = True) -> NodeGroupResult or None:
    """
    Generates and applies audit rules to the group
    :param group: Nodes group, where audit service should be configured
    :param now: Flag indicating that the audit service should be restarted immediately
    :return: Service restart result or nothing if audit rules are non exists, or restart is not required
    """
    cluster = group.cluster
    log = cluster.log

    if not is_audit_rules_defined(group.cluster.inventory):
        log.debug('Skipped - no audit rules in inventory')
        return

    log.debug('Applying audit rules...')
    rules_content = " \n".join(group.cluster.inventory['services']['audit']['rules'])

    rules_config_location = cluster.get_package_association_str_for_group(group, 'audit', 'config_location')

    utils.dump_file(group.cluster, rules_content, 'audit.rules')
    group.put(io.StringIO(rules_content), rules_config_location,
              sudo=True, backup=True)

    if now:
        return restart(group)
