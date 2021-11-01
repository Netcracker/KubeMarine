"""
This module works with audit on remote systems.
Using this module you can install audit and apply audit rules.
"""

import io

from kubetool import system, packages
from kubetool.core import utils
from kubetool.core.group import NodeGroup, NodeGroupResult


def install(group: NodeGroup, force=False) -> NodeGroupResult or None:
    log = group.cluster.log

    # This method supports cluster with multiple os, exceptions should be suppressed
    if not force and group.get_nodes_os(suppress_exceptions=True) in ['rhel', 'rhel8']:
        log.debug('Auditd installation is not required on RHEL nodes')
        return

    installation_group = group

    if not force:
        debian_nodes = group.get_nodes_with_os('debian')
        audit_installed_results = packages.detect_installed_package_version(debian_nodes, 'auditd')
        log.debug(audit_installed_results)
        installation_group = audit_installed_results.get_nonzero_nodes_group()
        if installation_group.nodes_amount() == 0:
            log.debug('Auditd is already installed on all nodes')
            return

    install_result = packages.install(installation_group, include='auditd')
    enable(group)
    return install_result


def enable(group):
    return system.enable_service(group, now=True)


def apply_audit_rules(group: NodeGroup) -> NodeGroupResult or None:
    """
    Generates and applies audit rules to the group.
    """

    log = group.cluster.log

    if group.get_nodes_os(suppress_exceptions=True) not in ['rhel', 'rhel8']:
        log.debug('Skipped - audit not supported on debian os family')
        return

    rules = group.cluster.inventory['services'].get('audit', {}).get('rules')
    if not rules:
        log.debug('Skipped - no audit rules in inventory')
        return

    log.debug('Applying audit rules...')
    rules_content = " \n".join(rules)

    utils.dump_file(group.cluster, rules_content, 'predefined.rules')
    group.put(io.StringIO(rules_content), '/etc/audit/rules.d/predefined.rules',
              sudo=True, backup=True)

    return group.sudo('service auditd restart')
