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
from typing import Set, List
from test.unit import utils as test_utils

from kubemarine.core import defaults, log
from kubemarine import demo, sysctl, kubernetes, modprobe
from kubemarine.core.group import NodeGroup


class DefaultsEnrichmentAppendControlPlain(unittest.TestCase):
    # pylint: disable=protected-access

    logger: log.EnhancedLogger = None

    @classmethod
    def setUpClass(cls):
        cls.logger = demo.new_cluster(demo.generate_inventory(**demo.ALLINONE)).log

    def test_controlplain_already_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'internal': '1.1.1.1',
            'external': '2.2.2.2'
        }
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '1.1.1.1')
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_already_internal_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'internal': '1.1.1.1'
        }
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '1.1.1.1')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_already_external_defined(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['control_plain'] = {
            'external': '2.2.2.2'
        }
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0])
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_calculated_half_vrrp_half_control_plane(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0])
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_calculated_fully_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['vrrp_ips'][0] = {
            'ip': '192.168.0.1',
            'floating_ip': inventory['vrrp_ips'][0]
        }
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][0]['ip'])
        self.assertEqual(inventory['control_plain']['external'], inventory['vrrp_ips'][0]['floating_ip'])

    def test_controlplain_calculated_half_fully_control_plane(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], inventory['nodes'][0]['internal_address'])
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_control_endpoint_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
                'floating_ip': '1.1.1.1'
            },
            {
                'ip': '192.168.0.2',
                'floating_ip': '2.2.2.2',
                'control_endpoint': True
            }
        ]
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_control_half_endpoint_vrrp(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
                'floating_ip': '1.1.1.1'
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], '1.1.1.1')

    def test_controlplain_control_half_endpoint_vrrp_half_control_plane(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_control_half_endpoint_vrrp_half_endpoint_control_plane(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.0.1',
            },
            {
                'ip': '192.168.0.2',
                'control_endpoint': True
            }
        ]
        inventory['nodes'][1]['control_endpoint'] = True
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.0.2')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][1]['address'])

    def test_controlplain_skip_not_bind(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.2.0',
                'floating_ip': '1.1.1.1',
                'params': {
                    'maintenance-type': 'not bind'
                }
            },
            {
                'ip': '192.168.2.1',
                'floating_ip': '2.2.2.2',
            }
        ]
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.2.1')
        self.assertEqual(inventory['control_plain']['external'], '2.2.2.2')

    def test_controlplain_skip_not_bind_half_vrrp_half_control_plane(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['vrrp_ips'] = [
            {
                'ip': '192.168.2.0',
                'floating_ip': '1.1.1.1',
                'params': {
                    'maintenance-type': 'not bind'
                }
            },
            {
                'ip': '192.168.2.1',
            }
        ]
        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], '192.168.2.1')
        self.assertEqual(inventory['control_plain']['external'], inventory['nodes'][0]['address'])

    def test_controlplain_skip_vrrp_ips_no_balancers(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=0, keepalived=1)
        first_control_plane = next(node for node in inventory['nodes'] if 'control-plane' in node['roles'])

        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], first_control_plane['internal_address'])
        self.assertEqual(inventory['control_plain']['external'], first_control_plane['address'])

    def test_controlplain_skip_vrrp_ips_assigned_not_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        first_control_plane = next(node for node in inventory['nodes'] if 'control-plane' in node['roles'])
        balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'hosts': [first_control_plane['name']]
        }

        defaults._append_controlplain(inventory, self.logger)
        self.assertEqual(inventory['control_plain']['internal'], balancer['internal_address'])
        self.assertEqual(inventory['control_plain']['external'], balancer['address'])

    def test_controlplain_skip_vrrp_ips_and_balancer_removed_only_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=1, keepalived=1)
        first_control_plane = next(node for node in inventory['nodes'] if 'control-plane' in node['roles'])
        balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])

        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [balancer]

        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context)
        inventory = cluster.inventory

        self.assertEqual(inventory['control_plain']['internal'], first_control_plane['internal_address'])
        self.assertEqual(inventory['control_plain']['external'], first_control_plane['address'])

    def test_controlplain_skip_vrrp_ips_assigned_to_removed_balancer(self):
        inventory = demo.generate_inventory(control_plane=3, worker=3, balancer=2, keepalived=2)
        first_balancer = next(node for node in inventory['nodes'] if 'balancer' in node['roles'])
        inventory['vrrp_ips'][0] = {
            'ip': inventory['vrrp_ips'][0],
            'hosts': [first_balancer['name']],
            'floating_ip': '1.1.1.1'
        }
        inventory['vrrp_ips'][1] = {
            'ip': inventory['vrrp_ips'][1],
            'floating_ip': '2.2.2.2'
        }

        context = demo.create_silent_context(['fake.yaml'], procedure='remove_node')
        remove_node = demo.generate_procedure_inventory('remove_node')
        remove_node['nodes'] = [first_balancer]

        cluster = demo.new_cluster(inventory, procedure_inventory=remove_node, context=context)
        inventory = cluster.inventory

        self.assertEqual(inventory['control_plain']['internal'], inventory['vrrp_ips'][1]['ip'])
        self.assertEqual(inventory['control_plain']['external'], inventory['vrrp_ips'][1]['floating_ip'])

    def test_single_control_plane(self):
        inventory = demo.generate_inventory(control_plane=['node-1'], worker=['node-1'], balancer=0)
        inventory['nodes'][0]['roles'].remove('worker')
        cluster = demo.new_cluster(inventory)
        self.assertTrue(cluster.make_group_from_roles(['worker']).is_empty())

    def test_error_no_control_planes_balancers(self):
        inventory = demo.generate_inventory(control_plane=0, worker=1, balancer=0)
        with test_utils.assert_raises_kme(self, 'KME0004'):
            demo.new_cluster(inventory)

    def test_error_no_control_planes(self):
        inventory = demo.generate_inventory(control_plane=0, worker=1, balancer=1)
        with test_utils.assert_raises_kme(self, 'KME0004'):
            demo.new_cluster(inventory)


class PrimitiveValuesAsString(unittest.TestCase):
    def test_default_enrichment(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('cri', {})['containerRuntime'] = 'containerd'
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.26.11'

        cluster = demo.new_cluster(inventory)
        inventory = cluster.inventory

        self.assertEqual(True, inventory['services']['cri']['containerdConfig']
                         ['plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options']['SystemdCgroup'])
        self.assertNotIn('min', inventory['services']['kubeadm_kube-proxy']['conntrack'])

        nginx_ingress_ports = inventory['plugins']['nginx-ingress-controller']['ports']
        self.assertEqual(20080, [port for port in nginx_ingress_ports if port['name'] == 'http'][0]['hostPort'])
        self.assertEqual(20443, [port for port in nginx_ingress_ports if port['name'] == 'https'][0]['hostPort'])

    def test_sysctl_override_blank(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        inventory['services']['sysctl'] = {
            'net.netfilter.nf_conntrack_max': ''
        }

        cluster = demo.new_cluster(inventory)

        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.netfilter.nf_conntrack_max', self._actual_sysctl_params(cluster, node),
                             "services.sysctl should not have net.netfilter.nf_conntrack_max if blank string is provided")
        self.assertIsNone(cluster.inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min'),
                          "services.kubeadm_kube-proxy should not have conntrack.min if blank string is provided")

        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        self.assertEqual('', finalized_inventory['services']['sysctl'].get('net.netfilter.nf_conntrack_max'),
                         "Finalized services.sysctl should have blank net.netfilter.nf_conntrack_max")
        self.assertIsNone(finalized_inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min'),
                          "services.kubeadm_kube-proxy should not have conntrack.min if blank string is provided")

        cluster = demo.new_cluster(finalized_inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.netfilter.nf_conntrack_max', self._actual_sysctl_params(cluster, node),
                             "services.sysctl should not have net.netfilter.nf_conntrack_max if blank string is provided")

    def test_default_v1_29_kube_proxy_conntrack_enrichment(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        inventory = demo.new_cluster(inventory).inventory

        self.assertEqual(1000000, inventory['services']['kubeadm_kube-proxy']['conntrack'].get('min'))

    def test_v1_29_kube_proxy_conntrack_overridden(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        inventory['services']['sysctl'] = {
            'net.netfilter.nf_conntrack_max': 1
        }
        inventory['services']['kubeadm_kube-proxy'] = {
            'conntrack': {'min': 2}
        }

        cluster = demo.new_cluster(inventory)

        self.assertEqual(1, cluster.inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min'),
                         "services.kubeadm_kube-proxy should always be overridden with net.netfilter.nf_conntrack_max")

        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        self.assertEqual(1, finalized_inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min'),
                         "Finalized services.kubeadm_kube-proxy should always be overridden with net.netfilter.nf_conntrack_max")

    def test_ambiguous_conntrack_max(self):
        inventory = demo.generate_inventory(control_plane=1, worker=1)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        inventory['services']['sysctl'] = {
            'net.netfilter.nf_conntrack_max': {
                'value': 1000000,
                'groups': ['control-plane']
            }
        }

        with self.assertRaisesRegex(Exception, kubernetes.ERROR_AMBIGUOUS_CONNTRACK_MAX.format(values='.*')):
            demo.new_cluster(inventory)

    def test_correct_conntrack_max_kubernetes_nodes(self):
        inventory = demo.generate_inventory(control_plane=1, worker=1)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        inventory['services']['sysctl'] = {
            'net.netfilter.nf_conntrack_max': {
                'value': 1000000,
                'groups': ['control-plane', 'worker']
            }
        }

        cluster = demo.new_cluster(inventory)
        self.assertEqual(1000000, cluster.inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min'))

    def test_custom_jinja_enrichment(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('modprobe', {})['debian'] = [
            """
            {% if true %}
            custom_module1
            {% endif %}
            """,
            """
            {% if false %}
            custom_module2
            {% endif %}
            """,
            {
                'modulename':
                    """
                    {{ 'custom_module3' }}
                    """,
                'install': '{{ "true" }}'
            },
            {
                'modulename': 'custom_module4',
                'install': '{{ "false" }}'
            },
            {'<<': 'merge'}
        ]

        inventory['services']['sysctl'] = {}
        inventory['services']['sysctl']['custom_parameter1'] = \
            """
            {% if true %}
            1
            {% endif %}
            """
        inventory['services']['sysctl']['custom_parameter2'] = {
            'value': "{% if true %}2{% endif %}",
            'install': '{{ "true" }}'
        }
        inventory['services']['sysctl']['custom_parameter3'] = {
            'value': 3,
            'install': '{{ "false" }}'
        }

        inventory['patches'] = [{
            'groups': ['control-plane', 'worker', 'balancer'],
            'services': {'sysctl': {
                'custom_parameter4':
                    """
                    {% if true %}
                    4
                    {% endif %}
                    """,
                'custom_parameter5': {
                    'value': "{% if true %}5{% endif %}",
                    'install': '{{ "true" }}'
                },
                'custom_parameter6': {
                    'value': 6,
                    'install': '{{ "false" }}'
                }
            }}
        }]

        inventory.setdefault('plugins', {}).setdefault('kubernetes-dashboard', {})['install'] = "{{ true }}"
        context = demo.create_silent_context()
        nodes_context = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='22.04')

        cluster = demo.new_cluster(inventory, context=context, nodes_context=nodes_context)
        inventory = cluster.inventory

        for node in cluster.nodes['all'].get_ordered_members_list():
            modules_list = self._actual_kernel_modules(node)
            self.assertEqual(['custom_module1', 'custom_module3', 'br_netfilter', 'nf_conntrack'],
                             modules_list)

        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertEqual(1, sysctl.get_parameter(cluster, node, 'custom_parameter1'))
            self.assertEqual(2, sysctl.get_parameter(cluster, node, 'custom_parameter2'))
            self.assertIsNone(sysctl.get_parameter(cluster, node, 'custom_parameter3'))
            self.assertEqual(4, sysctl.get_parameter(cluster, node, 'custom_parameter4'))
            self.assertEqual(5, sysctl.get_parameter(cluster, node, 'custom_parameter5'))
            self.assertIsNone(sysctl.get_parameter(cluster, node, 'custom_parameter3'))

            sysctl_config = sysctl.make_config(cluster, node)
            self.assertIn('custom_parameter1 = 1', sysctl_config)
            self.assertIn('custom_parameter2 = 2', sysctl_config)
            self.assertNotIn('custom_parameter3', sysctl_config)

            self.assertIn('custom_parameter4 = 4', sysctl_config)
            self.assertIn('custom_parameter5 = 5', sysctl_config)
            self.assertNotIn('custom_parameter6', sysctl_config)

        self.assertEqual(True, inventory['plugins']['kubernetes-dashboard']['install'])

    def test_recursive_reference_primitive_template(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'my_plugin': {
            'var1': '{% if plugins.my_plugin.install %}unexpected{% else %}ok{% endif %}',
            'install': '{{ "false" }}',
        }}

        cluster = demo.new_cluster(inventory)
        inventory = cluster.inventory
        self.assertEqual(False, inventory['plugins']['my_plugin']['install'])
        self.assertEqual('ok', inventory['plugins']['my_plugin']['var1'])

    def _actual_sysctl_params(self, cluster: demo.FakeKubernetesCluster, node: NodeGroup) -> Set[str]:
        return {
            record.split(' = ')[0]
            for record in sysctl.make_config(cluster, node).rstrip('\n').split('\n')
        }

    def _actual_kernel_modules(self, node: NodeGroup) -> List[str]:
        return modprobe.generate_config(node).rstrip('\n').split('\n')


if __name__ == '__main__':
    unittest.main()
