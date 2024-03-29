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

from kubemarine import demo, kubernetes
from kubemarine.core import flow
from kubemarine.procedures import reconfigure
from test.unit import utils as test_utils


class ReconfigureKubeadmEnrichment(unittest.TestCase):
    def setUp(self):
        self.setUpScheme(demo.ALLINONE)

    def setUpScheme(self, scheme: dict):
        self.inventory = demo.generate_inventory(**scheme)
        self.context = demo.create_silent_context(['fake.yaml'], procedure='reconfigure')

        self.reconfigure = demo.generate_procedure_inventory('reconfigure')
        self.reconfigure['services'] = {}

    def new_cluster(self) -> demo.FakeKubernetesCluster:
        return demo.new_cluster(self.inventory, procedure_inventory=self.reconfigure, context=self.context)

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
                {'nodes': ['master-1'], 'patch': {'api_kp2': 'api_vp2_new'}},
                {'<<': 'merge'}
            ],
            'kubelet': [
                {'groups': ['worker'], 'patch': {'kubelet_kp1': 'kubelet_vp1_new'}}
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
        self.assertEqual(enriched, 'master-1' in apiserver_certsans)

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
            {'nodes': ['master-1'], 'patch': {'api_kp2': 'api_vp2_new'}},
            {'groups': ['control-plane'], 'patch': {'api_kp1': 'api_vp1'}}
        ], kubeadm_patches['apiServer'])

        self.assertEqual([{'groups': ['worker'], 'patch': {'kubelet_kp1': 'kubelet_vp1_new'}}], kubeadm_patches['kubelet'])

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
        self.inventory.setdefault('rbac', {})['admission'] = 'pss'
        self.inventory['rbac']['pss'] = {'pod-security': 'enabled'}
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
                {'nodes': ['balancer-1'], 'patch': {'key': 'value'}},
            ]
        }
        with self.assertRaisesRegex(
                Exception, re.escape(kubernetes.ERROR_KUBELET_PATCH_NOT_KUBERNETES_NODE % 'kubelet')):
            self.new_cluster()

    def test_kubeadm_before_v1_25x_supports_patches(self):
        kubernetes_version = 'v1.24.11'
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = kubernetes_version
        self.reconfigure['services']['kubeadm_patches'] = {
            'apiServer': [
                {'nodes': ['master-1'], 'patch': {'api_key': 'api_value'}},
            ],
            'etcd': [
                {'groups': ['control-plane'], 'patch': {'etcd_key': 'api_value'}},
            ]
        }
        # No error should be raised
        self.new_cluster()

    def test_error_kubeadm_before_v1_25x_dont_support_patches_kubelet(self):
        kubernetes_version = 'v1.24.11'
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = kubernetes_version
        self.reconfigure['services']['kubeadm_patches'] = {
            'kubelet': [
                {'nodes': ['master-1'], 'patch': {'key': 'value'}},
            ]
        }
        with self.assertRaisesRegex(
                Exception, re.escape(kubernetes.ERROR_KUBEADM_DOES_NOT_SUPPORT_PATCHES_KUBELET.format(version=kubernetes_version))):
            self.new_cluster()


class RunTasks(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.reconfigure = demo.generate_procedure_inventory('reconfigure')
        self.reconfigure.setdefault('services', {})

    def _run_tasks(self, tasks_filter: str) -> demo.FakeResources:
        context = demo.create_silent_context(
            ['fake.yaml', '--tasks', tasks_filter], procedure='reconfigure')

        nodes_context = demo.generate_nodes_context(self.inventory)
        resources = demo.FakeResources(context, self.inventory,
                                       procedure_inventory=self.reconfigure, nodes_context=nodes_context)
        flow.run_actions(resources, [reconfigure.ReconfigureAction()])
        return resources

    def test_kubernetes_reconfigure_empty_procedure_inventory(self):
        self._run_tasks('deploy.kubernetes.reconfigure')

    def test_kubernetes_reconfigure_empty_sections(self):
        self.reconfigure['services'] = {
            'kubeadm': {'apiServer': {}, 'scheduler': {}, 'controllerManager': {}, 'etcd': {}},
            'kubeadm_kubelet': {},
            'kubeadm_kube-proxy': {},
        }
        with test_utils.mock_call(kubernetes.components.reconfigure_components) as run:
            self._run_tasks('deploy.kubernetes.reconfigure')

            actual_called = run.call_args[1]['components'] if run.called else []
            expected_called = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'kubelet', 'kube-proxy']
            self.assertEqual(expected_called, actual_called,
                             "Unexpected list of components to reconfigure")

    def test_kubernetes_reconfigure_empty_patch_sections(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.25.7'
        self.reconfigure.setdefault('services', {})['kubeadm_patches'] = {
            'apiServer': [], 'scheduler': [], 'controllerManager': [], 'etcd': [], 'kubelet': [],
        }
        with test_utils.mock_call(kubernetes.components.reconfigure_components) as run:
            self._run_tasks('deploy.kubernetes.reconfigure')

            actual_called = run.call_args[1]['components'] if run.called else []
            expected_called = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'kubelet']
            self.assertEqual(expected_called, actual_called,
                             "Unexpected list of components to reconfigure")

    def test_kubernetes_reconfigure_empty_apiserver_certsans(self):
        self.reconfigure['services'] = {
            'kubeadm': {'apiServer': {'certSANs': []}}
        }
        with test_utils.mock_call(kubernetes.components.reconfigure_components) as run:
            self._run_tasks('deploy.kubernetes.reconfigure')

            actual_called = run.call_args[1]['components'] if run.called else []
            expected_called = ['kube-apiserver/cert-sans', 'kube-apiserver']
            self.assertEqual(expected_called, actual_called,
                             "Unexpected list of components to reconfigure")


if __name__ == '__main__':
    unittest.main()
