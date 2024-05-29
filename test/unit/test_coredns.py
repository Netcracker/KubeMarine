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
from test.unit import utils as test_utils

from kubemarine import coredns, system, demo


class CorednsDefaultsEnrichment(unittest.TestCase):

    def test_add_hosts_config(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)
        configmap_hosts = '''127.0.0.1  localhost localhost.localdomain
10.101.2.1   k8s.fake.local control-plain
192.168.0.1  control-plane-1.k8s.fake.local control-plane-1
10.101.1.1   control-plane-1-external.k8s.fake.local control-plane-1-external
192.168.0.2  control-plane-2.k8s.fake.local control-plane-2
10.101.1.2   control-plane-2-external.k8s.fake.local control-plane-2-external
192.168.0.3  control-plane-3.k8s.fake.local control-plane-3
10.101.1.3   control-plane-3-external.k8s.fake.local control-plane-3-external
'''
        generated_hosts = system.generate_etc_hosts_config(cluster.inventory, 'etc_hosts_generated')
        default_hosts = system.generate_etc_hosts_config(cluster.inventory, 'etc_hosts')
        self.assertEqual(configmap_hosts, default_hosts + generated_hosts)

    def test_already_defined_hosts_config_and_not_add_etc_hosts_generated(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services'] = {
            'coredns': {
                'configmap': {
                    'Hosts': '1.2.3.4 example.org'
                }
            }
        }
        inventory['services']['coredns']['add_etc_hosts_generated'] = False
        cluster = demo.new_cluster(inventory)
        self.assertEqual('1.2.3.4 example.org', cluster.inventory['services']['coredns']['configmap']['Hosts'])


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
                                        'match': r'^(.*\.)?localhost\.$',
                                        'answer': '{{ .Name }} 3600 IN A 1.1.1.1'
                                    }
                                }
                            },
                            'forward': [
                                '.',
                                '/etc/resolv.conf',
                            ],
                        }
                    },
                    'Hosts': '127.0.0.1 localhost localhost.localdomain'
                }
            },
            'etc_hosts_generated': {
                '10.101.2.1': ['k8s.fake.local', 'control-plain'],
                '192.168.0.1': ['control-plane-1.k8s.fake.local', 'control-plane-1'],
                '10.101.1.1': ['control-plane-1-external.k8s.fake.local', 'control-plane-1-external'],
                '192.168.0.2':  ['control-plane-2.k8s.fake.local', 'control-plane-2'],
                '10.101.1.2':   ['control-plane-2-external.k8s.fake.local', 'control-plane-2-external'],
                '192.168.0.3':  ['control-plane-3.k8s.fake.local', 'control-plane-3'],
                '10.101.1.3':   ['control-plane-3-external.k8s.fake.local', 'control-plane-3-external']
            }
        }

        inventory['services']['coredns']['add_etc_hosts_generated'] = True
        config = coredns.generate_configmap(inventory)
        self.assertEqual(r'''apiVersion: v1

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
  Hosts: |
    127.0.0.1 localhost localhost.localdomain
    10.101.2.1   k8s.fake.local control-plain
    192.168.0.1  control-plane-1.k8s.fake.local control-plane-1
    10.101.1.1   control-plane-1-external.k8s.fake.local control-plane-1-external
    192.168.0.2  control-plane-2.k8s.fake.local control-plane-2
    10.101.1.2   control-plane-2-external.k8s.fake.local control-plane-2-external
    192.168.0.3  control-plane-3.k8s.fake.local control-plane-3
    10.101.1.3   control-plane-3-external.k8s.fake.local control-plane-3-external
    
''', config)

    def test_configmap_generation_with_hosts(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        cluster.inventory['services']['coredns']['add_etc_hosts_generated'] = True
        config = coredns.generate_configmap(cluster.inventory)
        self.assertIn('Hosts: |', config)
        self.assertIn('192.168.0.2  control-plane-1.k8s.fake.local', config)

    def test_configmap_generation_with_corefile_defaults(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)

        def test(cluster_: demo.FakeKubernetesCluster):
            config = coredns.generate_configmap(cluster_.inventory)
            self.assertIn('prometheus :9153', config)
            self.assertIn('cache 30', config)
            self.assertIn('loadbalance', config)
            self.assertIn('hosts /etc/coredns/Hosts', config)
            self.assertIn('template IN A k8s.fake.local', config)
            self.assertIn('forward . /etc/resolv.conf', config)
            self.assertIn('answer "{{ .Name }} 3600 IN A %s"' % (cluster_.inventory['control_plain']['internal'],), config)
            self.assertIn('authority "{{ .Name }} 3600 IN SOA', config)

        cluster = demo.new_cluster(inventory)
        test(cluster)

        cluster = demo.new_cluster(test_utils.make_finalized_inventory(cluster))
        test(cluster)

    def test_configmap_generation_with_corefile_defaults_disabled(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services']['coredns'] = {
            'configmap': {
                'Corefile': {
                    '.:53': {
                        'prometheus': False,
                        'loadbalance': False,
                        'hosts': False,
                        'forward': False
                    }
                }
            }
        }
        cluster = demo.new_cluster(inventory)
        config = coredns.generate_configmap(cluster.inventory)
        self.assertNotIn('prometheus :9153', config)
        self.assertIn('cache 30', config)
        self.assertNotIn('loadbalance', config)
        self.assertNotIn('hosts /etc/coredns/Hosts', config)
        self.assertIn('template IN A k8s.fake.local', config)
        self.assertNotIn('forward . /etc/resolv.conf', config)
        self.assertIn('answer "{{ .Name }} 3600 IN A %s"' % (cluster.inventory['control_plain']['internal'],), config)
        self.assertIn('authority "{{ .Name }} 3600 IN SOA', config)


if __name__ == '__main__':
    unittest.main()
