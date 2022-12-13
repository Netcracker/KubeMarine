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

import yaml

from kubemarine import system
from kubemarine.core import utils

import io


def enrich_add_hosts_config(inventory, cluster):
    if not inventory['services']['coredns']['configmap'].get('Hosts'):
        inventory['services']['coredns']['configmap']['Hosts'] = system.generate_etc_hosts_config(inventory, cluster)
    return inventory


def proceed_section_keyvalue(data, tabsize):
    tab = " "*tabsize
    config = ''

    for key, value in data.items():
        if isinstance(value, bool):
            if value:
                config += '\n' + tab + '%s' % key
            continue
        if isinstance(value, str) or isinstance(value, int) and value:
            if not isinstance(value, int) and any((c in set(' ')) for c in value):
                config += '\n' + tab + '%s \"%s\"' % (key, value)
            elif isinstance(value, str) and len(value) == 0:
                config += '\n' + tab + '%s' % key
            else:
                config += '\n' + tab + '%s %s' % (key, value)
            continue
        if isinstance(value, list) and value:
            config += '\n' + tab + '%s %s' % (key, " ".join(value))
            continue
        if isinstance(value, dict):
            config += generate_nested_sections(key, value, tabsize)
            continue
        raise Exception('Unknown type of field in coredns services')

    return config


def generate_nested_sections(type, data, tabsize):
    tab = " "*tabsize
    config = ''

    max_priority = 0
    for section_name, section_value in data.items():
        if section_value.get('priority') is not None and section_value['priority'] > max_priority:
            max_priority = section_value['priority']

    iterated = 0
    sections = []
    for section_name, section_value in data.items():
        if section_value.get('priority') is None:
            iterated += 1
            section_priority = max_priority + iterated
        else:
            section_priority = section_value['priority']

        if section_value.get('enabled', True) in ['1', 1, True, 'True']:
            sections.append({
                'name': section_name,
                'priority': section_priority
            })

    sections = sorted(sections, key=lambda i: i['priority'])

    for section in sections:

        if type == 'kubernetes':
            config += '\n' + tab + type
            if data[section['name']].get('zone'):
                if isinstance(data[section['name']]['zone'], list):
                    data[section['name']]['zone'] = ' '.join(data[section['name']]['zone'])
                config += ' ' + data[section['name']]['zone']
            config += ' {' + proceed_section_keyvalue(data[section['name']]['data'], tabsize + 2) + '\n' + tab + '}'

        elif type == 'hosts':
            config += '\n' + tab + type
            if data[section['name']].get('file') and isinstance(data[section['name']]['file'], str):
                config += ' ' + data[section['name']]['file']
            config += ' {' + proceed_section_keyvalue(data[section['name']]['data'], tabsize + 2) + '\n' + tab + '}'

        elif type == 'template':
            zones = [None]
            if data[section['name']].get('zone'):
                zones = data[section['name']]['zone']
                if isinstance(zones, str):
                    zones = [zones]
            for zone in zones:
                config += '\n' + tab + type
                if data[section['name']].get('class'):
                    config += ' ' + data[section['name']]['class']
                if data[section['name']].get('type'):
                    config += ' ' + data[section['name']]['type']
                if zone:
                    config += ' ' + zone
                config += ' {' + proceed_section_keyvalue(data[section['name']]['data'], tabsize + 2) + '\n' + tab + '}'

        else:
            config += '\n' + tab + type + ' {' + proceed_section_keyvalue(data[section['name']]['data'], tabsize + 2)\
                      + '\n' + tab + '}'

    return config


def generate_configmap(inventory):
    config = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:'''

    for config_type, data in inventory['services']['coredns']['configmap'].items():
        config += '\n  %s: |' % config_type
        if config_type == 'Corefile':
            for port, settings in data.items():
                config += '\n    %s {' % port
                config += proceed_section_keyvalue(settings, 6)
                config += '\n    }'
        else:
            config += '\n    ' + data.replace('\n', '\n    ')
    return config + '\n'


def apply_configmap(cluster, config):
    utils.dump_file(cluster, config, 'coredns-configmap.yaml')

    group = cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker')).get_final_nodes()
    group.put(io.StringIO(config), '/etc/kubernetes/coredns-configmap.yaml', backup=True, sudo=True)

    return cluster.nodes['control-plane'].get_final_nodes().get_first_member()\
        .sudo('kubectl apply -f /etc/kubernetes/coredns-configmap.yaml && '
             'sudo kubectl rollout restart -n kube-system deployment/coredns')


def apply_patch(cluster):
    apply_command = ''

    for config_type in ['deployment']:

        if not cluster.inventory['services']['coredns'].get(config_type):
            continue

        if apply_command != '':
            apply_command += ' && sudo '

        config = yaml.dump(cluster.inventory['services']['coredns'][config_type])
        filename = 'coredns-%s-patch.yaml' % config_type
        filepath = '/etc/kubernetes/' + filename

        utils.dump_file(cluster, config, filename)

        group = cluster.nodes['control-plane'].include_group(cluster.nodes.get('worker')).get_final_nodes()
        group.put(io.StringIO(config), filepath, backup=True, sudo=True)

        apply_command = 'kubectl patch %s coredns -n kube-system --type merge -p \"$(sudo cat %s)\"' % (config_type, filepath)

    if apply_command == '':
        return 'Nothing to patch'

    return cluster.nodes['control-plane'].get_final_nodes().get_first_member().sudo(apply_command)
