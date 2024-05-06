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

import json
from typing import Dict, List

from kubemarine.core import log
from kubemarine.core.group import NodeGroup, RunnersGroupResult


def get_status(group: NodeGroup) -> Dict[str, Dict[str, List[str]]]:
    log = group.cluster.log
    result = group.sudo("apparmor_status --json")
    parsed_result = {}
    for host, node_result in result.items():
        log.verbose('Parsing status for %s...' % host)
        parsed_result[host] = parse_status(log, node_result.stdout)
    print_status(log, parsed_result)
    return parsed_result


def parse_status(logger: log.EnhancedLogger, result_stdout: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    # Temporary workaround as long as we support OS with AppArmor from 3.0.0 to 3.0.8
    # Ubuntu 22.04.1 has 3.0.4
    # Malformed output is caused by false start `], ` delimiter
    # https://gitlab.com/apparmor/apparmor/-/blob/v3.0.4/binutils/aa_status.c#L537
    # https://gitlab.com/apparmor/apparmor/-/issues/295
    if '"processes": {], ' in result_stdout:
        logger.debug("Patching malformed apparmor_status --json output")
        result_stdout = result_stdout.replace('"processes": {], ', '"processes": {')

    parsed_data = json.loads(result_stdout)
    for profile_name, profile_state in parsed_data['profiles'].items():
        result.setdefault(profile_state, []).append(profile_name)

    return result


def print_status(logger: log.EnhancedLogger, parsed_result: dict) -> None:
    res = "AppArmor Status:"
    for state in parsed_result.keys():
        res += "\n  Profiles in %s mode:" % state
        for profile in parsed_result[state]:
            res += "\n    - %s" % profile
    logger.verbose(res)


def is_state_valid(group: NodeGroup, expected_profiles: Dict[str, List[str]]) -> bool:
    log = group.cluster.log

    log.verbose('Verifying Apparmor modes...')

    parsed_result = get_status(group)
    valid = True

    for host, status in parsed_result.items():
        for state, profiles in expected_profiles.items():
            if not profiles:
                continue
            if state == 'disable':
                for profile in profiles:
                    if any(profile in remote_profiles for remote_profiles in status.values()):
                        valid = False
                        log.verbose('Mode %s is enabled on remote host %s' % (state, host))
                        break
            else:
                if not status.get(state):
                    valid = False
                    log.verbose('Mode %s is not presented on remote host %s' % (state, host))
                    break
                # check if all 'cluster.yaml' settings reflect on particular node
                for profile in profiles:
                    if profile not in status[state]:
                        valid = False
                        log.verbose('Profile %s is not enabled in %s mode on remote host %s' % (profile, state, host))
                        break

    return valid


# TODO: describe what the purpose of that method is
def convert_profile(profile: str) -> str:
    profile = profile.replace('/', '.')
    if profile[0] == '.':
        profile = profile[1:]
    return profile


def configure_apparmor(group: NodeGroup, expected_profiles: dict) -> RunnersGroupResult:
    cmd = ''
    for profile in expected_profiles.get('enforce', []):
        profile = convert_profile(profile)
        cmd += (f'sudo rm -f /etc/apparmor.d/disable/{profile}; '
                f'sudo rm -f /etc/apparmor.d/force-complain/{profile}; ')
    for profile in expected_profiles.get('complain', []):
        profile = convert_profile(profile)
        cmd += (f'sudo rm -f /etc/apparmor.d/disable/{profile}; '
                f'sudo ln -s /etc/apparmor.d/{profile} /etc/apparmor.d/force-complain/; ')
    for profile in expected_profiles.get('disable', []):
        profile = convert_profile(profile)
        cmd += (f'sudo rm -f /etc/apparmor.d/force-complain/{profile}; '
                f'sudo ln -s /etc/apparmor.d/{profile} /etc/apparmor.d/disable/; ')
    cmd += 'sudo systemctl reload apparmor.service && sudo apparmor_status'
    return group.sudo(cmd)


def setup_apparmor(group: NodeGroup) -> bool:
    log = group.cluster.log

    if group.get_nodes_os() != 'debian':
        log.debug("Skipped - Apparmor is supported only on Ubuntu/Debian")
        return False

    expected_profiles = group.cluster.inventory['services']['kernel_security'].get('apparmor', {})
    valid = is_state_valid(group, expected_profiles)

    if valid:
        log.debug("Skipped - Apparmor already correctly configured")
        return False

    group.call(configure_apparmor, expected_profiles=expected_profiles)

    return True
