#!/usr/bin/env python3
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


import unittest

from kubemarine import coredns, system, demo


class CorednsDefaultsEnrichment(unittest.TestCase):

    def test_add_hosts_config(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)
        generated_hosts = system.generate_etc_hosts_config(cluster.inventory)
        self.assertEquals(generated_hosts, cluster.inventory['services']['coredns'].get('configmap').get('Hosts'))

    def test_already_defined_hosts_config(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services'] = {
            'coredns': {
                'configmap': {
                    'Hosts': '1.2.3.4 example.org'
                }
            }
        }
        cluster = demo.new_cluster(inventory)
        self.assertEquals('1.2.3.4 example.org', cluster.inventory['services']['coredns']['configmap']['Hosts'])


class CorednsGenerator(unittest.TestCase):

    def test_configmap_generation(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services'] = {
            'coredns': {
                'configmap': {
                    'Corefile': {
                        '.:53': {
                            'errors': True,
                            'prometheus': ':9153',
                            'cache': 30,
                            'kubernetes': {
                                'default': {
                                    'zone': [
                                        'test'
                                    ],
                                    'data': {
                                        'pods': 'insecure',
                                        'fallthrough': [
                                            'ip6.arpa'
                                        ],
                                        'ttl': 30
                                    }
                                }
                            },
                            'template': {
                                'default': {
                                    'class': 'IN',
                                    'type': 'A',
                                    'zone': 'test',
                                    'data': {
                                        'match': '^(.*\.)?localhost\.$',
                                        'answer': '{{ .Name }} 3600 IN A 1.1.1.1'
                                    }
                                }
                            },
                            'forward': [
                                '.',
                                '/etc/resolv.conf',
                            ],
                        }
                    }
                }
            }
        }

        config = coredns.generate_configmap(inventory)
        self.assertEqual('''apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      errors
      prometheus :9153
      cache 30
      kubernetes test {
        pods insecure
        fallthrough ip6.arpa
        ttl 30
      }
      template IN A test {
        match ^(.*\.)?localhost\.$
        answer "{{ .Name }} 3600 IN A 1.1.1.1"
      }
      forward . /etc/resolv.conf
    }
''', config)

    def test_configmap_generation_with_hosts(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        config = coredns.generate_configmap(cluster.inventory)
        self.assertIn('Hosts: |', config)
        self.assertIn('192.168.0.2  master-1.k8s.fake.local', config)
