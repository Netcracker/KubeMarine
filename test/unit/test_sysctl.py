import re
import unittest
from copy import deepcopy
from typing import Set

from kubemarine import demo, sysctl
from kubemarine.core.group import NodeGroup


def nodes_having_parameter(cluster: demo.FakeKubernetesCluster, parameter: str) -> Set[str]:
    return {node.get_node_name() for node in cluster.nodes['all'].get_ordered_members_list()
            if parameter in sysctl.make_config(cluster, node)}


def actual_sysctl_params(cluster: demo.FakeKubernetesCluster, node: NodeGroup) -> Set[str]:
    return {
        record.split(' = ')[0]
        for record in sysctl.make_config(cluster, node).rstrip('\n').split('\n')
    }


class ParametersEnrichment(unittest.TestCase):
    def test_make_config_all_nodes_simple_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': 1}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'parameter = 1'))
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertIn('parameter', actual_sysctl_params(cluster, node))

    def test_make_config_empty_value(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': ''}
        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('parameter', actual_sysctl_params(cluster, node))

    def test_make_config_all_nodes_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_specific_group(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'groups': ['control-plane']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'master-1'},
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_specific_nodes(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        specific_nodes = ['balancer-1', 'worker-1']
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'nodes': specific_nodes
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(specific_nodes),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_groups_nodes(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'groups': ['worker'], 'nodes': ['balancer-1']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'balancer-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_unknown_nodes(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'nodes': ['unknown-node']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_parameter_not_install(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'install': False
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_override_default_simple_format_all_nodes(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-ip6tables': 0}

        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-ip6tables = 0'))

    def test_override_default_extended_format_default_groups(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-iptables': {
            'value': 0
        }}

        cluster = demo.new_cluster(inventory)
        self.assertEqual({'master-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 0'))
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 1'))

    def test_override_default_add_nodes(self):
        inventory = demo.generate_inventory(balancer=2, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-iptables': {
            'value': 1,
            'nodes': ['balancer-2']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'balancer-2', 'master-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 1'))

    def test_override_not_installed_default(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-ip6tables': {
            'value': 0
        }}
        cluster = demo.new_cluster(deepcopy(inventory))
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-ip6tables = 0'))

        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-ip6tables': {
            'value': '0', 'install': True
        }}
        cluster = demo.new_cluster(deepcopy(inventory))
        self.assertEqual(set(cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_names()),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-ip6tables = 0'))

    def test_override_default_simple_format_empty_value(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.ipv4.ip_forward': ''}

        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.ipv4.ip_forward', actual_sysctl_params(cluster, node))

    def test_override_default_extended_format_not_install(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'net.ipv4.ip_forward': {
            'value': 0, 'install': False
        }}

        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.ipv4.ip_forward', actual_sysctl_params(cluster, node))

    def test_error_invalid_integer_value_simple_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': 'test'}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value 'test' "
                                                         "in section ['services']['sysctl']['parameter']")):
            demo.new_cluster(inventory)

    def test_error_invalid_integer_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 'test'
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value 'test' "
                                                         "in section ['services']['sysctl']['parameter']['value']")):
            demo.new_cluster(inventory)

    def test_error_empty_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': ''
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value '' "
                                                         "in section ['services']['sysctl']['parameter']['value']")):
            demo.new_cluster(inventory)

    def test_error_invalid_install_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': '1', 'install': 'test'
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid truth value 'test' "
                                                         "in section ['services']['sysctl']['parameter']['install']")):
            demo.new_cluster(inventory)

    def test_default_enrichment(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        cluster = demo.new_cluster(inventory)

        for node in cluster.nodes['all'].get_ordered_members_list():
            if 'balancer' in node.get_config()['roles']:
                expected_params = {'net.ipv4.ip_nonlocal_bind'}
            else:
                expected_params = {
                    'net.bridge.bridge-nf-call-iptables', 'net.ipv4.ip_forward',
                    'net.ipv4.conf.all.route_localnet', 'net.netfilter.nf_conntrack_max',
                    'kernel.panic', 'vm.overcommit_memory', 'kernel.panic_on_oops', 'kernel.pid_max'}

            actual_params = actual_sysctl_params(cluster, node)
            self.assertEqual(expected_params, actual_params)

    def test_ipv6_default_enrichment(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        for i, node in enumerate(inventory['nodes']):
            node['internal_address'] = f'2001::{i + 1}'

        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            if 'balancer' in node.get_config()['roles']:
                expected_params = {'net.ipv4.ip_nonlocal_bind', 'net.ipv6.ip_nonlocal_bind'}
            else:
                expected_params = {
                    'net.bridge.bridge-nf-call-iptables', 'net.bridge.bridge-nf-call-ip6tables', 'net.ipv4.ip_forward',
                    'net.ipv4.conf.all.route_localnet', 'net.ipv6.conf.all.forwarding', 'net.netfilter.nf_conntrack_max',
                    'kernel.panic', 'vm.overcommit_memory', 'kernel.panic_on_oops', 'kernel.pid_max'}

            actual_params = actual_sysctl_params(cluster, node)
            self.assertEqual(expected_params, actual_params)

    def test_kubelet_doesnt_protect_kernel_defaults(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['kubeadm_kubelet'] = {
            'protectKernelDefaults': False,
        }
        cluster = demo.new_cluster(inventory)

        for node in cluster.nodes['all'].get_ordered_members_list():
            if 'balancer' in node.get_config()['roles']:
                expected_params = {'net.ipv4.ip_nonlocal_bind'}
            else:
                expected_params = {
                    'net.bridge.bridge-nf-call-iptables', 'net.ipv4.ip_forward',
                    'net.ipv4.conf.all.route_localnet', 'net.netfilter.nf_conntrack_max',
                    'kernel.pid_max'}

            actual_params = actual_sysctl_params(cluster, node)
            self.assertEqual(expected_params, actual_params)


class KernelPidMax(unittest.TestCase):
    def test_default_value_default_kubelet_config(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_names()),
                         nodes_having_parameter(cluster, f'kernel.pid_max = 452608'))

    def test_default_value_custom_kubelet_config(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 1,
            'podPidsLimit': 1,
        }
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_names()),
                         nodes_having_parameter(cluster, f'kernel.pid_max = 2049'))

    def test_error_not_set(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'kernel.pid_max': {
            'value': 2 ** 22,
            'groups': ['balancer', 'control-plane']
        }}
        with self.assertRaisesRegex(Exception, re.escape(sysctl.ERROR_PID_MAX_NOT_SET.format(node='worker-1'))):
            demo.new_cluster(inventory)

    def test_error_exceeds(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['sysctl'] = {'kernel.pid_max': {
            'value': 2 ** 22 + 1
        }}
        with self.assertRaisesRegex(Exception, re.escape(sysctl.ERROR_PID_MAX_EXCEEDS.format(
                node='master-1', value=2 ** 22 + 1, max=2 ** 22))):
            demo.new_cluster(inventory)

    def test_error_less_than_required(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['sysctl'] = {'kernel.pid_max': {
            'value': 10000
        }}
        with self.assertRaisesRegex(Exception, re.escape(sysctl.ERROR_PID_MAX_REQUIRED.format(
                node='master-1', value=10000, required=452608))):
            demo.new_cluster(inventory)

    def test_error_less_than_required_kubelet_patch(self):
        inventory = demo.generate_inventory(balancer=1, master=1, worker=1)
        inventory['services']['sysctl'] = {'kernel.pid_max': 110 * 4096 + 2048}
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 100, 'podPidsLimit': 4000,
        }
        inventory['services']['kubeadm_patches'] = {
            'kubelet': [
                {
                    'groups': ['control-plane', 'worker'],
                    'patch': {'maxPods': 110, 'podPidsLimit': 4096}
                },
                {
                    'nodes': ['worker-1'],
                    'patch': {'maxPods': 111}
                }
            ]
        }
        with self.assertRaisesRegex(Exception, re.escape(sysctl.ERROR_PID_MAX_REQUIRED.format(
                node='worker-1', value=110 * 4096 + 2048, required=111 * 4096 + 2048))):
            demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
