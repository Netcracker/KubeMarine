"""
This module works with audit on remote systems.
Using this module you can apply audit rules.
"""

import io

from kubetool import system
from kubetool.core import utils
from kubetool.core.group import NodeGroup, NodeGroupResult


def apply_audit_rules(group: NodeGroup) -> NodeGroupResult or None:
    """
    Generates and applies audit rules to the group.
    """

    log = group.cluster.log

    # TODO: fix this - currently audit preinstalled only on Centos/RHEL, but not presented on Ubuntu/Debian
    if system.get_os_family(group.cluster) not in ['rhel', 'rhel8']:
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
