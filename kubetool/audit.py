"""
This module works with audit on remote systems.
Using this module you can install, enable audit and configure audit rules.
"""

import io

from kubetool import system, packages
from kubetool.core import utils
from kubetool.core.executor import RemoteExecutor
from kubetool.core.group import NodeGroup, NodeGroupResult


def is_audit_rules_defined(inventory):
    rules = inventory['services'].get('audit', {}).get('rules')
    return rules is not None


def install(group: NodeGroup, enable_service=True, force=False) -> NodeGroupResult or None:
    # This method does not support multi-os groups
    if group.is_multi_os():
        raise Exception('Audit installation is not supported on multi-os group')

    cluster = group.cluster
    log = cluster.log

    if not is_audit_rules_defined(cluster.inventory):
        log.debug('Skipped - no audit rules in inventory')
        return

    # This method supports cluster with multiple os, exceptions should be suppressed
    if not force and group.get_nodes_os(suppress_exceptions=True) in ['rhel', 'rhel8']:
        log.debug('Auditd installation is not required on RHEL nodes')
        return

    install_group = group

    if not force:
        log.verbose('Searching for already installed auditd package...')
        debian_group = group.get_subgroup_with_os('debian')
        debian_package_name = cluster.get_package_association_str_for_group(debian_group, 'audit', 'package_name')
        audit_installed_results = packages.detect_installed_package_version(debian_group, debian_package_name)
        log.verbose(audit_installed_results)

        # Reduce nodes amount for installation
        install_group = audit_installed_results.get_nonzero_nodes_group()

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


def enable(group, now=True):
    # This method does not support multi-os groups
    if group.is_multi_os():
        raise Exception('Enabling Audit is not supported on a multi-os group')

    cluster = group.cluster

    service_name = cluster.get_package_association_str_for_group(group, 'audit', 'service_name')
    return system.enable_service(group, name=service_name, now=now)


def restart(group):
    # This method does not support multi-os groups
    if group.is_multi_os():
        raise Exception('Audit restart is not supported on a multi-os group')

    cluster = group.cluster

    service_name = cluster.get_package_association_str_for_group(group, 'audit', 'service_name')
    return group.sudo(f'service {service_name} restart')


def apply_audit_rules(group: NodeGroup) -> NodeGroupResult or None:
    """
    Generates and applies audit rules to the group.
    """

    # This method does not support multi-os groups
    if group.is_multi_os():
        raise Exception('Audit configuring is not supported on multi-os group')

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

    return restart(group)
