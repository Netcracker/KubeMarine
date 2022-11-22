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

from kubemarine import system


def get_status(group):
    log = group.cluster.log
    result = group.sudo("apparmor_status --json")
    parsed_result = {}
    if result:
        for connection, node_result in result.items():
            log.verbose('Parsing status for %s...' % connection.host)
            parsed_result[connection] = parse_status(node_result.stdout)
    print_status(log, parsed_result)
    return parsed_result


def parse_status(result_stdout):
    result = {}
    parsed_data = json.loads(result_stdout)
    modes_set = set()
    for mode in parsed_data['profiles'].values():
        modes_set.add(mode)
    for mode in modes_set:
        profile_list = []
        for profile_name, profile_state in parsed_data['profiles'].items():
            if profile_state == mode:
                profile_list.append(profile_name)
        result[profile_state] = profile_list
    return result


def print_status(log, parsed_result):
    res = "AppArmor Status:"
    for state in parsed_result.keys():
        res += "\n  Profiles in %s mode:" % state
        for profile in parsed_result[state]:
            res += "\n    - %s" % profile
    log.verbose(res)


def is_state_valid(group, expected_profiles):
    log = group.cluster.log

    log.verbose('Verifying Apparmor modes...')

    parsed_result = get_status(group)
    valid = True

    for connection, status in parsed_result.items():
        for state, profiles in expected_profiles.items():
            if not profiles:
                continue
            if state == 'disable':
                for profile in profiles:
                    for remote_profiles in status.values():
                        if profile in remote_profiles:
                            valid = False
                            log.verbose('Mode %s is enabled on remote host %s' % (state, connection.host))
                            break
            else:
                if not status.get(state):
                    valid = False
                    log.verbose('Mode %s is not presented on remote host %s' % (state, connection.host))
                    break
                # check if all 'cluster.yaml' settings reflect on particular node
                for profile in profiles:
                    if profile not in status[state]:
                        valid = False
                        log.verbose('Profile %s is not enabled in %s mode on remote host %s' % (profile, state, connection.host))
                        break

    return valid, parsed_result

# TODO: describe what the purpose of that method is
def convert_profile(profile):
    profile = profile.replace('/', '.')
    if profile[0] == '.':
        profile = profile[1:]
    return profile


def configure_apparmor(group, expected_profiles):
    cmd = ''
    for profile in expected_profiles.get('enforce', []):
        profile = convert_profile(profile)
        cmd += 'sudo rm -f /etc/apparmor.d/disable/%s; sudo rm -f /etc/apparmor.d/force-complain/%s; ' % (profile, profile)
    for profile in expected_profiles.get('complain', []):
        profile = convert_profile(profile)
        cmd += 'sudo rm -f /etc/apparmor.d/disable/%s; sudo ln -s /etc/apparmor.d/%s /etc/apparmor.d/force-complain/; ' % (profile, profile)
    for profile in expected_profiles.get('disable', []):
        profile = convert_profile(profile)
        cmd += 'sudo rm -f /etc/apparmor.d/force-complain/%s; sudo ln -s /etc/apparmor.d/%s /etc/apparmor.d/disable/; ' % (profile, profile)
    cmd += 'sudo systemctl reload apparmor.service && sudo apparmor_status'
    return group.sudo(cmd)


def setup_apparmor(group):
    log = group.cluster.log

    if group.get_nodes_os() != 'debian':
        log.debug("Skipped - Apparmor is supported only on Ubuntu/Debian")
        return

    expected_profiles = group.cluster.inventory['services']['kernel_security'].get('apparmor', {})
    valid, parsed_result = is_state_valid(group, expected_profiles)

    if valid:
        log.debug("Skipped - Apparmor already correctly configured")
        return

    log.debug(configure_apparmor(group, expected_profiles))
    group.cluster.schedule_cumulative_point(system.reboot_nodes)
    group.cluster.schedule_cumulative_point(system.verify_system)
