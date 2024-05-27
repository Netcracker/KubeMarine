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
from contextlib import contextmanager
from typing import Set, List

from test.unit import utils as test_utils

from kubemarine import demo, kubernetes, sysctl
from kubemarine.core import flow
from kubemarine.procedures import reconfigure


class _AbstractReconfigureTest(unittest.TestCase):
    def setUp(self):
        self.setUpScheme(demo.ALLINONE)

    def setUpScheme(self, scheme: dict):
        self.inventory = demo.generate_inventory(**scheme)
        self.context = demo.create_silent_context(['fake.yaml', '--without-act'], procedure='reconfigure')

        self.reconfigure = demo.generate_procedure_inventory('reconfigure')
        self.reconfigure['services'] = {}

    def new_resources(self) -> demo.FakeResources:
        nodes_context = demo.generate_nodes_context(self.inventory)
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.reconfigure, nodes_context=nodes_context)

    def new_cluster(self) -> demo.FakeKubernetesCluster:
        with test_utils.unwrap_fail():
            return self.new_resources().cluster()

    def run_action(self) -> demo.FakeResources:
        resources = self.new_resources()
        flow.run_actions(resources, [reconfigure.ReconfigureAction()])
        return resources


class ReconfigureKubeadmEnrichment(_AbstractReconfigureTest):
    def test_enrich_and_finalize_inventory(self):
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': 'v1.25.7',
            'apiServer': {
                'extraArgs': {'api_k1': 'api_v1'},
                'extraVolumes': [{'name': 'api_name1', 'hostPath': '/home/path', 'mountPath': '/mount/path'}],
                'certSANs': ['san1'],
                'timeoutForControlPlane': '4m0s',
            },
            'scheduler': {
                'extraArgs': {'sched_key1': 'sched_v1'},
            },
            'controllerManager': {
                'extraVolumes': [{'name': 'ctrl_name1', 'hostPath': '/home/path', 'mountPath': '/mount/path'}],
            },
            'etcd': {'local': {
                'extraArgs': {'etcd_k1': 'etcd_v1'},
                'imageTag': '1.2.3'
            }},
        }
        self.reconfigure['services']['kubeadm'] = {
            'apiServer': {
                'extraArgs': {'api_k1': 'api_v1_new', 'api_k2': 'api_v2_new'},
                'extraVolumes': [
                    {'<<': 'merge'},
                    {'name': 'api_name2_new', 'hostPath': '/home/path', 'mountPath': '/mount/path'}
                ],
                'certSANs': ['san2_new'],
                'timeoutForControlPlane': '5m0s',
            },
            'scheduler': {
                'extraVolumes': [{'name': 'sched_name1_new', 'hostPath': '/home/path', 'mountPath': '/mount/path'}],
            },
            'controllerManager': {
                'extraArgs': {'ctrl_k1': 'ctrl_k1_new'},
            },
            'etcd': {'local': {
                'extraArgs': {'etcd_k1': 'etcd_v1_new'},
            }},
        }

        self.inventory['services']['kubeadm_kubelet'] = {
            'enableDebuggingHandlers': False,
            'serializeImagePulls': True
        }
        self.reconfigure['services']['kubeadm_kubelet'] = {
            'serializeImagePulls': False
        }

        self.inventory['services']['kubeadm_kube-proxy'] = {
            'logging': {'format': 'test-format'}
        }
        self.reconfigure['services']['kubeadm_kube-proxy'] = {
            'logging': {'verbosity': 5}
        }

        self.inventory['services']['kubeadm_patches'] = {
            'apiServer': [{'groups': ['control-plane'], 'patch': {'api_kp1': 'api_vp1'}}]
        }
        self.reconfigure['services']['kubeadm_patches'] = {
            'apiServer': [
                {'nodes': ['control-plane-1'], 'patch': {'api_kp2': 'api_vp2_new'}},
                {'<<': 'merge'}
            ],
            'kubelet': [
                {'groups': ['worker'], 'patch': {'maxPods': 111}}
            ]
        }

        cluster = self.new_cluster()
        services = cluster.inventory['services']
        self._test_enrich_and_finalize_inventory_check(services, True)

        services = test_utils.make_finalized_inventory(cluster)['services']
        self._test_enrich_and_finalize_inventory_check(services, True)

        services = cluster.formatted_inventory['services']
        self._test_enrich_and_finalize_inventory_check(services, False)

    def _test_enrich_and_finalize_inventory_check(self, services: dict, enriched: bool):
        apiserver_args = services['kubeadm']['apiServer']['extraArgs'].items()
        self.assertIn(('api_k1', 'api_v1_new'), apiserver_args)
        self.assertIn(('api_k2', 'api_v2_new'), apiserver_args)
        self.assertEqual(enriched, ('profiling', 'false') in apiserver_args)

        apiserver_volumes = services['kubeadm']['apiServer']['extraVolumes']
        self.assertIn({'name': 'api_name1', 'hostPath': '/home/path', 'mountPath': '/mount/path'}, apiserver_volumes)
        self.assertIn({'name': 'api_name2_new', 'hostPath': '/home/path', 'mountPath': '/mount/path'}, apiserver_volumes)

        apiserver_certsans = services['kubeadm']['apiServer']['certSANs']
        self.assertNotIn('san1', apiserver_certsans)
        self.assertIn('san2_new', apiserver_certsans)
        self.assertEqual(enriched, 'control-plane-1' in apiserver_certsans)

        self.assertEqual('5m0s', services['kubeadm']['apiServer']['timeoutForControlPlane'])

        scheduler_args = services['kubeadm']['scheduler']['extraArgs'].items()
        self.assertIn(('sched_key1', 'sched_v1'), scheduler_args)
        self.assertEqual(enriched, ('profiling', 'false') in scheduler_args)

        scheduler_volumes = services['kubeadm']['scheduler']['extraVolumes']
        self.assertIn({'name': 'sched_name1_new', 'hostPath': '/home/path', 'mountPath': '/mount/path'}, scheduler_volumes)

        ctrl_args = services['kubeadm']['controllerManager']['extraArgs'].items()
        self.assertIn(('ctrl_k1', 'ctrl_k1_new'), ctrl_args)
        self.assertEqual(enriched, ('profiling', 'false') in ctrl_args)

        ctrl_volumes = services['kubeadm']['controllerManager']['extraVolumes']
        self.assertIn({'name': 'ctrl_name1', 'hostPath': '/home/path', 'mountPath': '/mount/path'}, ctrl_volumes)

        etcd_args = services['kubeadm']['etcd']['local']['extraArgs'].items()
        self.assertIn(('etcd_k1', 'etcd_v1_new'), etcd_args)

        self.assertEqual('1.2.3', services['kubeadm']['etcd']['local']['imageTag'])

        kubelet = services['kubeadm_kubelet']
        self.assertEqual(False, kubelet['enableDebuggingHandlers'])
        self.assertEqual(False, kubelet['serializeImagePulls'])
        self.assertEqual(enriched, kubelet.get('cgroupDriver') == 'systemd')

        kube_proxy = services['kubeadm_kube-proxy']
        self.assertEqual({'format': 'test-format', 'verbosity': 5}, kube_proxy['logging'])

        kubeadm_patches = services['kubeadm_patches']
        self.assertEqual([
            {'nodes': ['control-plane-1'], 'patch': {'api_kp2': 'api_vp2_new'}},
            {'groups': ['control-plane'], 'patch': {'api_kp1': 'api_vp1'}}
        ], kubeadm_patches['apiServer'])

        self.assertEqual([{'groups': ['worker'], 'patch': {'maxPods': 111}}], kubeadm_patches['kubelet'])

    def test_change_apiserver_args_check_jinja_dependent_parameters(self):
        self.reconfigure['services']['kubeadm'] = {
            'apiServer': {
                'extraArgs': {'audit-policy-file': '/changed/path'},
            }
        }

        cluster = self.new_cluster()

        apiserver = cluster.inventory['services']['kubeadm']['apiServer']
        self.assertEqual('/changed/path', apiserver['extraArgs']['audit-policy-file'])
        self.assertEqual('/changed/path', apiserver['extraVolumes'][0]['hostPath'])
        self.assertEqual('/changed/path', apiserver['extraVolumes'][0]['mountPath'])

    def test_pss_managed_arg_not_redefined(self):
        self.reconfigure['services']['kubeadm'] = {
            'apiServer': {
                'extraArgs': {'admission-control-config-file': '/some/redefined/path'},
            },
        }

        inventory = self.new_cluster().inventory
        # This is a potential subject for change.
        # The behaviour just follows historical behaviour if installation procedure.
        self.assertEqual('/etc/kubernetes/pki/admission.yaml',
                         inventory['services']['kubeadm']['apiServer']['extraArgs']['admission-control-config-file'])

    def test_error_control_plane_patch_refers_worker(self):
        self.setUpScheme(demo.FULLHA)
        self.reconfigure['services']['kubeadm_patches'] = {
            'apiServer': [
                {'nodes': ['worker-1'], 'patch': {'key': 'value'}},
            ]
        }
        with self.assertRaisesRegex(
                Exception, re.escape(kubernetes.ERROR_CONTROL_PLANE_PATCH_NOT_CONTROL_PLANE_NODE % 'apiServer')):
            self.new_cluster()

    def test_error_kubelet_patch_refers_balancer(self):
        self.setUpScheme(demo.FULLHA)
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.25.7'
        self.reconfigure['services']['kubeadm_patches'] = {
            'kubelet': [
                {'nodes': ['balancer-1'], 'patch': {'maxPods': 111}},
            ]
        }
        with self.assertRaisesRegex(
                Exception, re.escape(kubernetes.ERROR_KUBELET_PATCH_NOT_KUBERNETES_NODE % 'kubelet')):
            self.new_cluster()

    def test_kubeadm_supports_patches(self):
        kubernetes_version = 'v1.25.2'
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = kubernetes_version
        self.reconfigure['services']['kubeadm_patches'] = {
            'apiServer': [
                {'nodes': ['control-plane-1'], 'patch': {'api_key': 'api_value'}},
            ],
            'etcd': [
                {'groups': ['control-plane'], 'patch': {'etcd_key': 'api_value'}},
            ],
            'kubelet': [
                {'nodes': ['control-plane-1'], 'patch': {'maxPods': 111}},
            ],
        }
        # No error should be raised
        self.new_cluster()


class ReconfigureSysctlEnrichment(_AbstractReconfigureTest):
    def setUp(self):
        self.setUpScheme({'balancer': 1, 'control_plane': 1, 'worker': 1})

    def test_enrich_and_finalize_inventory(self):
        self.inventory['services']['sysctl'] = {
            'parameter1': 1,
            'parameter3': {
                'value': 1,
            },
            'parameter4': 1,
            'parameter5': {
                'value': 1,
            },
            'parameter6': 1,
            'parameter7': {
                'value': 1
            },
            'parameter8': 1,
        }
        self.reconfigure['services']['sysctl'] = {
            'parameter1': 2,
            'parameter2': 2,
            'parameter3': '{{ "2" }}',
            'parameter4': {
                'value': 2,
                'groups': ['control-plane'],
            },
            'parameter5': {
                'value': '2',
                'nodes': ['worker-1'],
            },
            'parameter6': '',
            'parameter7': {
                'value': 0,
                'install': '{{ "False" }}',
            },
        }

        self.inventory['patches'] = [
            {
                'groups': ['control-plane', 'worker'],
                'services': {'sysctl': {
                    'parameter8': 2,
                }}
            },
        ]
        self.reconfigure['patches'] = [
            {
                'groups': ['control-plane'],
                'services': {'sysctl': {
                    'parameter8': 3,
                }}
            },
        ]

        resources = self.run_action()
        cluster = resources.cluster_if_initialized()
        self._test_enrich_and_finalize_inventory_check(cluster)

        cluster2 = demo.new_cluster(resources.finalized_inventory)
        self._test_enrich_and_finalize_inventory_check(cluster2)

        cluster3 = demo.new_cluster(resources.inventory())
        self._test_enrich_and_finalize_inventory_check(cluster3)

    def _test_enrich_and_finalize_inventory_check(self, cluster: demo.FakeKubernetesCluster):
        all_nodes = {'balancer-1', 'control-plane-1', 'worker-1'}
        self.assertEqual(all_nodes, self._nodes_having_parameter(cluster, 'parameter1 = 2'))
        self.assertEqual(all_nodes, self._nodes_having_parameter(cluster, 'parameter2 = 2'))
        self.assertEqual(all_nodes, self._nodes_having_parameter(cluster, 'parameter3 = 2'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter4 = 1'))
        self.assertEqual({'control-plane-1'}, self._nodes_having_parameter(cluster, 'parameter4 = 2'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter5 = 1'))
        self.assertEqual({'worker-1'}, self._nodes_having_parameter(cluster, 'parameter5 = 2'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter6 = 1'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter6 = 2'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter7 = 1'))
        self.assertEqual(set(), self._nodes_having_parameter(cluster, 'parameter7 = 2'))
        self.assertEqual({'balancer-1'}, self._nodes_having_parameter(cluster, 'parameter8 = 1'))
        self.assertEqual({'worker-1'}, self._nodes_having_parameter(cluster, 'parameter8 = 2'))
        self.assertEqual({'control-plane-1'}, self._nodes_having_parameter(cluster, 'parameter8 = 3'))

    def test_invalid(self):
        for name, parameter, msg, in (
                (
                        'invalid_integer_value',
                        {'parameter': 'test'},
                        "invalid integer value 'test' "
                        "in section ['services']['sysctl']['parameter']"
                ),
                (
                        'invalid_integer_value_extended_format',
                        {'parameter': {'value': 'test'}},
                        "invalid integer value 'test' "
                        "in section ['services']['sysctl']['parameter']['value']"
                ),
                (
                        'kernel.pid_max_error_less_than_required',
                        {'kernel.pid_max': 10000},
                        sysctl.ERROR_PID_MAX_REQUIRED.format(node='control-plane-1', value=10000, required=452608)
                ),
                (
                        'ambiguous_conntrack_max',
                        {'net.netfilter.nf_conntrack_max': {'value': 10000, 'groups':['control-plane']}},
                        kubernetes.ERROR_AMBIGUOUS_CONNTRACK_MAX.format(values='{10000, None}')
                ),
        ):
            for patch in (False, True):
                if patch:
                    msg = msg.replace("['services']", "['patches'][0]['services']")
                with self.subTest(f'{name}, patch: {patch}'), test_utils.assert_raises_regex(self, Exception, re.escape(msg)):
                    self.setUp()
                    if patch:
                        self.reconfigure['patches'] = [
                            {
                                'groups': ['control-plane', 'worker', 'balancer'],
                                'services': {'sysctl': parameter}
                            }
                        ]
                    else:
                        self.reconfigure['services']['sysctl'] = parameter

                    self.run_action()

    @staticmethod
    def _nodes_having_parameter(cluster: demo.FakeKubernetesCluster, parameter: str) -> Set[str]:
        return {node.get_node_name() for node in cluster.nodes['all'].get_ordered_members_list()
                if parameter in sysctl.make_config(cluster, node)}


class RunTasks(_AbstractReconfigureTest):
    def _run(self) -> demo.FakeResources:
        # pylint: disable-next=attribute-defined-outside-init
        self.context = demo.create_silent_context(
            ['fake.yaml', '--tasks', 'prepare.system.sysctl,deploy.kubernetes.reconfigure'], procedure='reconfigure')

        return self.run_action()

    def test_empty_procedure_inventory(self):
        with self._sysctl_reconfigured(False), self._kubernetes_components_reconfigured([]):
            self._run()

    def test_prepare_sysctl_empty_section(self):
        self.reconfigure['services']['sysctl'] = {}
        with self._sysctl_reconfigured(True), self._kubernetes_components_reconfigured([]):
            self._run()

    def test_kubernetes_reconfigure_empty_sections(self):
        self.reconfigure['services'] = {
            'kubeadm': {'apiServer': {}, 'scheduler': {}, 'controllerManager': {}, 'etcd': {}},
            'kubeadm_kubelet': {},
            'kubeadm_kube-proxy': {},
        }
        expected_called = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'kubelet', 'kube-proxy']
        with self._sysctl_reconfigured(False), self._kubernetes_components_reconfigured(expected_called):
            self._run()

    def test_kubernetes_reconfigure_empty_patch_sections(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.25.7'
        self.reconfigure.setdefault('services', {})['kubeadm_patches'] = {
            'apiServer': [], 'scheduler': [], 'controllerManager': [], 'etcd': [], 'kubelet': [],
        }
        expected_called = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'kubelet']
        with self._sysctl_reconfigured(False), self._kubernetes_components_reconfigured(expected_called):
            self._run()

    def test_kubernetes_reconfigure_empty_apiserver_certsans(self):
        self.reconfigure['services'] = {
            'kubeadm': {'apiServer': {'certSANs': []}}
        }
        expected_called = ['kube-apiserver/cert-sans', 'kube-apiserver']
        with self._sysctl_reconfigured(False), self._kubernetes_components_reconfigured(expected_called):
            self._run()

    def test_kubernetes_reconfigure_detect_kube_proxy_conntrack_min_changes(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.29.1'
        self.reconfigure['services']['sysctl'] = {
            'net.netfilter.nf_conntrack_max': 1000001
        }
        expected_called = ['kube-proxy']
        with self._sysctl_reconfigured(True), self._kubernetes_components_reconfigured(expected_called):
            res = self._run()
            self.assertEqual(1000001, res.working_inventory['services']['kubeadm_kube-proxy']['conntrack'].get('min'))

    def test_prepare_sysctl_detect_changes_kubelet_maxPods_changed(self):
        self.reconfigure['services']['kubeadm_patches'] = {
            'kubelet': [
                {'nodes': ['control-plane-1'], 'patch': {'maxPods': 105}},
            ]
        }
        expected_called = ['kubelet']
        with self._sysctl_reconfigured(True), self._kubernetes_components_reconfigured(expected_called):
            res = self._run()
            cluster = res.cluster_if_initialized()
            control_plane_1 = cluster.make_group_from_nodes(['control-plane-1'])
            control_plane_1_config = cluster.nodes_inventory[control_plane_1.get_host()]
            self.assertEqual(432128, control_plane_1_config['services']['sysctl']['kernel.pid_max']['value'])

    def test_prepare_sysctl_detect_changes_kubelet_protectKernelDefaults_changed(self):
        self.reconfigure['services']['kubeadm_kubelet'] = {
            'protectKernelDefaults': False
        }
        expected_called = ['kubelet']
        with self._sysctl_reconfigured(True), self._kubernetes_components_reconfigured(expected_called):
            res = self._run()
            cluster = res.cluster_if_initialized()
            for node in cluster.nodes['all'].get_ordered_members_list():
                sysctl_config = sysctl.make_config(cluster, node)
                for unexpected_parameter in ('kernel.panic', 'vm.overcommit_memory', 'kernel.panic_on_oops'):
                    self.assertNotIn(unexpected_parameter, sysctl_config)

    @contextmanager
    def _kubernetes_components_reconfigured(self, expected_called: List[str]):
        with test_utils.mock_call(kubernetes.components.reconfigure_components) as run:
            yield

            actual_called = run.call_args[1]['components'] if run.called else []
            self.assertEqual(expected_called, actual_called,
                             "Unexpected list of components to reconfigure")

    @contextmanager
    def _sysctl_reconfigured(self, reconfigured: bool):
        with test_utils.mock_call(sysctl.configure), \
                test_utils.mock_call(sysctl.reload), \
                test_utils.mock_call(sysctl.is_valid, side_effect=[False, True]) as is_valid_run:
            yield

            expected_call_count = 2 if reconfigured else 0
            self.assertEqual(expected_call_count, is_valid_run.call_count, "Unexpected number of sysctl.is_valid calls")


if __name__ == '__main__':
    unittest.main()
