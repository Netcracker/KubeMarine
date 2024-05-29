# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import unittest
from copy import deepcopy
from typing import Set
from test.unit import utils as test_utils

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
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': 1}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'parameter = 1'))
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertIn('parameter', actual_sysctl_params(cluster, node))

    def test_make_config_empty_value(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': ''}
        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('parameter', actual_sysctl_params(cluster, node))

    def test_make_config_all_nodes_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_specific_group(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'groups': ['control-plane']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'control-plane-1'},
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_specific_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        specific_nodes = ['balancer-1', 'worker-1']
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'nodes': specific_nodes
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(specific_nodes),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_groups_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'groups': ['worker'], 'nodes': ['balancer-1']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'balancer-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_unknown_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'nodes': ['unknown-node']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_make_config_parameter_not_install(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 1, 'install': False
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'parameter = 1'))

    def test_override_default_simple_format_all_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-ip6tables': 0}

        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.nodes['all'].get_nodes_names()),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-ip6tables = 0'))

    def test_override_default_extended_format_default_groups(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-iptables': {
            'value': 0
        }}

        cluster = demo.new_cluster(inventory)
        self.assertEqual({'control-plane-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 0'))
        self.assertEqual(set(),
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 1'))

    def test_override_default_add_nodes(self):
        inventory = demo.generate_inventory(balancer=2, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'net.bridge.bridge-nf-call-iptables': {
            'value': 1,
            'nodes': ['balancer-2']
        }}
        cluster = demo.new_cluster(inventory)
        self.assertEqual({'balancer-2', 'control-plane-1', 'worker-1'},
                         nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 1'))

    def test_override_not_installed_default(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'net.ipv4.ip_forward': ''}

        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.ipv4.ip_forward', actual_sysctl_params(cluster, node))

    def test_override_default_extended_format_not_install(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'net.ipv4.ip_forward': {
            'value': 0, 'install': False
        }}

        cluster = demo.new_cluster(inventory)
        for node in cluster.nodes['all'].get_ordered_members_list():
            self.assertNotIn('net.ipv4.ip_forward', actual_sysctl_params(cluster, node))

    def test_error_invalid_integer_value_simple_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': 'test'}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value 'test' "
                                                         "in section ['services']['sysctl']['parameter']")):
            demo.new_cluster(inventory)

    def test_error_invalid_integer_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': 'test'
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value 'test' "
                                                         "in section ['services']['sysctl']['parameter']['value']")):
            demo.new_cluster(inventory)

    def test_error_empty_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': ''
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid integer value '' "
                                                         "in section ['services']['sysctl']['parameter']['value']")):
            demo.new_cluster(inventory)

    def test_error_invalid_install_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'parameter': {
            'value': '1', 'install': 'test'
        }}
        with self.assertRaisesRegex(Exception, re.escape("invalid truth value 'test' "
                                                         "in section ['services']['sysctl']['parameter']['install']")):
            demo.new_cluster(inventory)

    def test_default_enrichment(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_names()),
                         nodes_having_parameter(cluster, f'kernel.pid_max = 452608'))

    def test_default_value_custom_kubelet_config(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 1,
            'podPidsLimit': 1,
        }
        cluster = demo.new_cluster(inventory)
        self.assertEqual(set(cluster.make_group_from_roles(['control-plane', 'worker']).get_nodes_names()),
                         nodes_having_parameter(cluster, f'kernel.pid_max = 2049'))

    def test_default_value_custom_kubelet_config_and_patches(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=2, worker=2)
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 1,
            'podPidsLimit': 1,
        }
        inventory['services']['kubeadm_patches'] = {
            'kubelet': [
                {
                    'groups': ['worker'],
                    'patch': {'maxPods': 2, 'podPidsLimit': 2}
                },
                {
                    'nodes': ['control-plane-1', 'worker-1'],
                    'patch': {'maxPods': 3}
                }
            ]
        }

        def test(cluster_: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2051'))
            self.assertEqual({'control-plane-2'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2049'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2054'))
            self.assertEqual({'worker-2'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2052'))

        cluster = demo.new_cluster(inventory)
        test(cluster)

        cluster = demo.new_cluster(test_utils.make_finalized_inventory(cluster))
        test(cluster)

    def test_override_global_kubelet_config_and_patches(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {'kernel.pid_max': {
            'value': 2 ** 22,
        }}
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 1,
            'podPidsLimit': 1,
        }
        inventory['services']['kubeadm_patches'] = {
            'kubelet': [
                {
                    'groups': ['worker'],
                    'patch': {'maxPods': 2, 'podPidsLimit': 2}
                }
            ]
        }

        cluster = demo.new_cluster(inventory)
        self.assertEqual({'control-plane-1', 'worker-1'},
                         nodes_having_parameter(cluster, f'kernel.pid_max = {2 ** 22}'))

    def test_override_patches_kubelet_config_and_patches(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=2)
        inventory['patches'] = [
            {
                'nodes': ['worker-1'],
                'services': {'sysctl': {
                    'kernel.pid_max': 2 ** 22,
                }}
            }
        ]
        inventory['services']['kubeadm_kubelet'] = {
            'maxPods': 1,
            'podPidsLimit': 1,
        }
        inventory['services']['kubeadm_patches'] = {
            'kubelet': [
                {
                    'groups': ['worker'],
                    'patch': {'maxPods': 2, 'podPidsLimit': 2}
                },
            ]
        }

        def test(cluster_: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2049'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster_, f'kernel.pid_max = {2 ** 22}'))
            self.assertEqual({'worker-2'},
                             nodes_having_parameter(cluster_, 'kernel.pid_max = 2052'))

        cluster = demo.new_cluster(inventory)
        test(cluster)

        cluster = demo.new_cluster(test_utils.make_finalized_inventory(cluster))
        test(cluster)

    def test_error_not_set(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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
                node='control-plane-1', value=2 ** 22 + 1, max=2 ** 22))):
            demo.new_cluster(inventory)

    def test_error_less_than_required(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['sysctl'] = {'kernel.pid_max': {
            'value': 10000
        }}
        with self.assertRaisesRegex(Exception, re.escape(sysctl.ERROR_PID_MAX_REQUIRED.format(
                node='control-plane-1', value=10000, required=452608))):
            demo.new_cluster(inventory)

    def test_error_less_than_required_kubelet_patch(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
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


class PatchesEnrichmentAndFinalization(unittest.TestCase):
    def patch_groups_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['patches'] = [
            {
                'groups': ['control-plane'],
                'nodes': ['balancer-1'],
                'services': {'sysctl': {
                    'parameter': 1,
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1', 'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter = 1'))

        yield test

    def patch_unknown_nodes(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['patches'] = [
            {
                'nodes': ['unknown-node'],
                'services': {'sysctl': {
                    'parameter': 1
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter = 1'))

        yield test

    def patch_different_values(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker'],
                'services': {'sysctl': {'parameter': 0}}
            },
            {
                'groups': ['balancer'],
                'services': {'sysctl': {'parameter': 1}}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'parameter = 0'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter = 1'))

        yield test

    def override_specific_nodes(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {
            'parameter1': 1,
            'parameter2': 1,
            'parameter3': 1,
            'parameter4': 1,
            'parameter5': 1,
            'parameter6': 1,
        }
        inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker'],
                'services': {'sysctl': {
                    'parameter1': 2,
                    'parameter2': {
                        'value': 2
                    },
                    'parameter3': '',
                    'parameter4': {
                        'value': 1,
                        'install': False,
                    },
                    'parameter5': {
                        'value': 1,
                        'groups': ['control-plane']
                    },
                    'parameter6': {
                        'value': 1,
                        'nodes': ['control-plane-1']
                    },
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter1 = 1'))
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'parameter1 = 2'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter2 = 1'))
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'parameter2 = 2'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter3 = 1'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter4 = 1'))
            self.assertEqual({'balancer-1', 'control-plane-1'},
                             nodes_having_parameter(cluster, 'parameter5 = 1'))
            self.assertEqual({'balancer-1', 'control-plane-1'},
                             nodes_having_parameter(cluster, 'parameter6 = 1'))

        yield test

    def override_value_extended_format(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {
            'parameter1': {
                'value': 1,
                'groups': ['control-plane']
            },
            'parameter2': {
                'value': 1,
                'groups': ['control-plane']
            },
            'parameter3': {
                'value': 1,
            },
            'parameter4': {
                'value': 1,
                'install': False
            },
            'parameter5': {
                'value': 1,
                'install': False
            },
        }
        inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker'],
                'services': {'sysctl': {
                    'parameter1': 2,
                    'parameter2': {
                        'value': 2
                    },
                    'parameter3': {
                        'value': 2,
                        'nodes': ['worker-1']
                    },
                    'parameter4': {
                        'value': 2
                    },
                    'parameter5': {
                        'value': 2,
                        'install': True,
                    },
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter1 = 1'))
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'parameter1 = 2'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter2 = 1'))
            self.assertEqual({'control-plane-1'},
                             nodes_having_parameter(cluster, 'parameter2 = 2'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter3 = 1'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster, 'parameter3 = 2'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter4 = 1'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter4 = 2'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'parameter5 = 1'))
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'parameter5 = 2'))

        yield test

    def override_few_times(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=4)
        inventory['services']['sysctl'] = {
            'parameter': 0,
        }
        inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker'],
                'services': {'sysctl': {'parameter': 1}}
            },
            {
                'nodes': ['worker-1'],
                'services': {'sysctl': {'parameter': 2}}
            },
            {
                'nodes': ['worker-3', 'worker-4'],
                'services': {'sysctl': {'parameter': {
                    'value': 3
                }}}
            },
            {
                'nodes': ['worker-4'],
                'services': {'sysctl': {'parameter': {
                    'value': 0,
                    'install': False,
                }}}
            },
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'parameter = 0'))
            self.assertEqual({'control-plane-1', 'worker-2'},
                             nodes_having_parameter(cluster, 'parameter = 1'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster, 'parameter = 2'))
            self.assertEqual({'worker-3'},
                             nodes_having_parameter(cluster, 'parameter = 3'))

        yield test

    def patches_override_defaults(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker', 'balancer'],
                'services': {'sysctl': {
                    'net.ipv4.ip_forward': 0,
                    'net.bridge.bridge-nf-call-iptables': {
                        'value': 0
                    },
                    'net.bridge.bridge-nf-call-ip6tables': {
                        'value': 0
                    },
                    'net.ipv6.ip_nonlocal_bind': {
                        'value': 0,
                        'install': True
                    },
                    'kernel.panic': '',
                    'vm.overcommit_memory': {
                        'value': 0,
                        'install': False
                    },
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1', 'worker-1', 'balancer-1'},
                             nodes_having_parameter(cluster, 'net.ipv4.ip_forward = 0'))
            self.assertEqual({'control-plane-1', 'worker-1'},
                             nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 0'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-iptables = 1'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'net.bridge.bridge-nf-call-ip6tables = 0'))
            self.assertEqual({'balancer-1'},
                             nodes_having_parameter(cluster, 'net.ipv6.ip_nonlocal_bind = 0'))

            for node in cluster.nodes['all'].get_ordered_members_list():
                self.assertNotIn('kernel.panic', actual_sysctl_params(cluster, node))
                self.assertNotIn('vm.overcommit_memory', actual_sysctl_params(cluster, node))

                expected_present = bool(set(node.get_config()['roles']) & {'control-plane', 'worker'})
                self.assertEqual(expected_present, 'kernel.panic_on_oops' in actual_sysctl_params(cluster, node))

        yield test

    def sysctl_and_patches_override_defaults(self):
        inventory = demo.generate_inventory(balancer=1, control_plane=1, worker=1)
        inventory['services']['sysctl'] = {
            'net.ipv4.ip_forward': 0,
            'kernel.panic': '',
            'vm.overcommit_memory': 0,
        }
        inventory['patches'] = [
            {
                'groups': ['worker'],
                'services': {'sysctl': {
                    'net.ipv4.ip_forward': 1,
                    'kernel.panic': 10,
                    'vm.overcommit_memory': '',
                }}
            }
        ]

        yield inventory

        def test(cluster: demo.FakeKubernetesCluster):
            self.assertEqual({'control-plane-1', 'balancer-1'},
                             nodes_having_parameter(cluster, 'net.ipv4.ip_forward = 0'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster, 'net.ipv4.ip_forward = 1'))
            self.assertEqual({'worker-1'},
                             nodes_having_parameter(cluster, 'kernel.panic = 10'))
            self.assertEqual({'control-plane-1', 'balancer-1'},
                             nodes_having_parameter(cluster, 'vm.overcommit_memory = 0'))
            self.assertEqual(set(),
                             nodes_having_parameter(cluster, 'vm.overcommit_memory = 1'))

        yield test

    def test_valid(self):
        for tc_func in (
            self.patch_unknown_nodes,
            self.patch_groups_nodes,
            self.patch_different_values,
            self.override_specific_nodes,
            self.override_value_extended_format,
            self.override_few_times,
            self.patches_override_defaults,
            self.sysctl_and_patches_override_defaults,
        ):
            with self.subTest(tc_func.__name__):
                tc = tc_func()

                inventory = next(tc)
                test = next(tc)

                cluster = demo.new_cluster(inventory)
                test(cluster)

                cluster = demo.new_cluster(test_utils.make_finalized_inventory(cluster))
                test(cluster)

    def test_invalid(self):
        for name, parameter, msg, in (
                (
                        'invalid_integer_value_simple_format',
                        {'parameter': 'test'},
                        "invalid integer value 'test' "
                        "in section ['patches'][0]['services']['sysctl']['parameter']"
                ),
                (
                        'invalid_integer_value_extended_format',
                        {'parameter': {'value': 'test'}},
                        "invalid integer value 'test' "
                        "in section ['patches'][0]['services']['sysctl']['parameter']['value']"
                ),
                (
                        'empty_value_extended_format',
                        {'parameter': {'value': ''}},
                        "invalid integer value '' "
                        "in section ['patches'][0]['services']['sysctl']['parameter']['value']"
                ),
                (
                        'invalid_install_value_extended_format',
                        {'parameter': {'value': 0, 'install': 'test'}},
                        "invalid truth value 'test' "
                        "in section ['patches'][0]['services']['sysctl']['parameter']['install']"
                ),
        ):
            with self.subTest(name):
                inventory = demo.generate_inventory(**demo.ALLINONE)
                inventory['patches'] = [
                    {
                        'groups': ['control-plane', 'worker', 'balancer'],
                        'services': {'sysctl': parameter}
                    }
                ]
                with self.assertRaisesRegex(Exception, re.escape(msg)):
                    demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
