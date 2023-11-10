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
import re
from typing import Tuple, Optional, Dict, List

from kubemarine import system
from kubemarine.core import utils, log
from kubemarine.core.group import NodeGroup, RunnersGroupResult

# Common regexp should support the following schemes:
# SELinux status:                 enabled
# SELinuxfs mount:                /selinux
# Policy version:                 23

# Commong regexp
common_regexp = "%s:\\s*([\\w/\\d]*)"

# Structure with names to parse and keys to put the data to parsed map:
parsed_names_map = {
    re.compile(common_regexp % 'SELinux status', re.M):             'status',
    re.compile(common_regexp % 'SELinuxfs mount', re.M):            'mount',
    re.compile(common_regexp % 'SELinux root directory', re.M):     'root_directory',
    re.compile(common_regexp % 'Current mode', re.M):               'mode',
    re.compile(common_regexp % 'Mode from config file', re.M):      'mode_from_file',
    re.compile(common_regexp % 'Loaded policy name', re.M):         'policy',
    re.compile(common_regexp % 'Policy from config file', re.M):    'policy_from_file',
    re.compile(common_regexp % 'Policy MLS status', re.M):          'policy_mls',
    re.compile(common_regexp % 'Policy deny_unknown status', re.M): 'policy_deny_unknown',
    re.compile(common_regexp % 'Policy version', re.M):             'policy_version',
    re.compile(common_regexp % 'Max kernel policy version', re.M):  'policy_version_max'
}

# Cutomized permissive types regexp
# It should from the following:
#
# > Customized Permissive Types
# >
# > keepalived_t
# > something_else_t
# >
# > Builtin Permissive Types
# >
# > and_another_one
#
# Cut only the following:
#
# > keepalived_t
# > something_else_t
#
permissive_types_regex = re.compile("Customized Permissive Types\\s*([\\w_\\s]*)\\s*", re.M)


def get_expected_state(inventory: dict) -> str:
    state: str = inventory['services']['kernel_security'].get('selinux', {}).get('state', 'enforcing')
    return state


def get_expected_policy(inventory: dict) -> str:
    policy: str = inventory['services']['kernel_security'].get('selinux', {}).get('policy', 'targeted')
    return policy


def get_expected_permissive(inventory: dict) -> List[str]:
    permissive: List[str] = inventory['services']['kernel_security'].get('selinux', {}).get('permissive', [])
    return permissive


def parse_selinux_status(logger: log.EnhancedLogger, stdout: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if stdout is not None and stdout.strip() != '':
        for regex, key in parsed_names_map.items():
            matches: List[str] = re.findall(regex, stdout)
            if matches:
                result[key] = matches[0].strip()
    logger.verbose('Parsed status: %s' % result)
    return result


def parse_selinux_permissive_types(logger: log.EnhancedLogger, stdout: str) -> List[str]:
    if stdout is None or stdout.strip() == '':
        logger.verbose('Permissive types pattern not found - presented stdout is empty')
        return []

    matches: List[str] = re.findall(permissive_types_regex, stdout)
    if not matches:
        logger.verbose('Permissive types pattern not found')
        return []

    types_string = matches[0]
    if types_string.strip() == '':
        logger.verbose('Permissive types pattern found, but value is empty')
        return []

    result = types_string.split('\n')
    logger.verbose('Permissive types parsed: %s' % result)
    return result


def get_selinux_status(group: NodeGroup) -> Tuple[RunnersGroupResult, Dict[str, dict]]:
    log = group.cluster.log

    result = group.sudo("sestatus && sudo semanage permissive -l")

    parsed_result: Dict[str, dict] = {}
    for host, node_result in result.items():
        log.verbose('Parsing status for %s...' % host)
        parsed_result[host] = parse_selinux_status(log, node_result.stdout)
        parsed_result[host]['permissive_types'] = parse_selinux_permissive_types(log, node_result.stdout)
    log.verbose("Parsed remote sestatus summary:\n%s" % parsed_result)
    return result, parsed_result


def is_config_valid(group: NodeGroup, state: str = None, policy: str = None, permissive: List[str] = None) \
        -> Tuple[bool, RunnersGroupResult, Dict[str, dict]]:
    log = group.cluster.log

    if group.get_nodes_os() == 'debian':
        raise Exception("Selinux is not supported on Ubuntu/Debian os family")

    log.verbose('Verifying selinux configs...')

    if state is None:
        state = get_expected_state(group.cluster.inventory)

    if policy is None:
        policy = get_expected_policy(group.cluster.inventory)

    if permissive is None:
        permissive = get_expected_permissive(group.cluster.inventory)

    result, parsed_result = get_selinux_status(group)
    valid = True

    for host, selinux_status in parsed_result.items():

        if selinux_status['status'] == 'disabled' and state == 'disabled':
            continue

        # for some different selinux versions some statuses may be absent
        # that is why such construction was made - when no status, then cause true
        if state != selinux_status.get('mode', state) or \
                state != selinux_status.get('mode_from_file', state) or \
                policy != selinux_status.get('policy_from_file', policy) or \
                policy != selinux_status.get('policy', policy):
            valid = False
            log.verbose('Selinux configs are not matched at %s' % host)
            break

        if permissive:
            for permissive_type in permissive:
                if permissive_type not in selinux_status['permissive_types']:
                    valid = False
                    log.verbose('Permissive type %s not found in types %s at %s '
                                % (permissive_type, selinux_status['permissive_types'], host))
                    break
            # if no break was called in previous for loop, then else called and no break will be called in current loop
            else:
                continue
            # if break was called in previous for loop, then do break in current loop
            break

    return valid, result, parsed_result


def setup_selinux(group: NodeGroup) -> Optional[RunnersGroupResult]:
    log = group.cluster.log

    # this method handles cluster with multiple os, suppressing should be enabled
    if group.get_nodes_os() not in ['rhel', 'rhel8', 'rhel9']:
        log.debug("Skipped - selinux is not supported on Ubuntu/Debian os family")
        return None

    expected_state = get_expected_state(group.cluster.inventory)
    expected_policy = get_expected_policy(group.cluster.inventory)
    expected_permissive = get_expected_permissive(group.cluster.inventory)

    valid, result, parsed_result = is_config_valid(group,
                                                   state=expected_state,
                                                   policy=expected_policy,
                                                   permissive=expected_permissive)

    if valid:
        log.debug("Skipped - selinux already correctly configured")
        return result

    config = io.StringIO('SELINUX=%s\nSELINUXTYPE=%s\n' % (expected_state, expected_policy))

    log.debug("Uploading selinux config...")
    utils.dump_file(group.cluster, config, 'selinux_config')
    group.put(config, '/etc/selinux/config', backup=True, sudo=True)

    semanage_commands = ''
    for item in expected_permissive:
        if semanage_commands != '':
            semanage_commands = semanage_commands + ' && sudo '
        semanage_commands = semanage_commands + 'semanage permissive -a %s' % item
    log.verbose("The following command will be executed to configure permissive:\n%s" % semanage_commands)

    group.sudo(semanage_commands)

    group.cluster.schedule_cumulative_point(system.reboot_nodes)
    group.cluster.schedule_cumulative_point(system.verify_system)
    return None
