#!/usr/bin/env python3

import unittest

from kubetool import coredns, system, demo


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
