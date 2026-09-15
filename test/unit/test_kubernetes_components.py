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

import json
import random
import re
import unittest
from contextlib import contextmanager
from copy import deepcopy
from unittest import mock
from typing import List
from test.unit import utils as test_utils

import yaml
from ordered_set import OrderedSet

from kubemarine import demo, plugins, system, kubernetes
from kubemarine.kubernetes import components


class KubeadmConfigTest(unittest.TestCase):
    def test_worker_join_upload_uses_v1beta4_arguments(self):
        self._check_worker_join_upload('v1.37.0')

    def test_worker_join_upload_preserves_v1beta3_for_older_versions(self):
        self._check_worker_join_upload('v1.36.0')

    def _check_worker_join_upload(self, version):
        group = mock.Mock()
        group.is_empty.return_value = False
        group.get_ordered_members_list.return_value = []
        group.cluster.context = {'join_dict': {}}
        group.cluster.inventory = {'services': {'kubeadm': {'kubernetesVersion': version}}}
        join = {'apiVersion': 'kubeadm.k8s.io/v1beta3', 'kind': 'JoinConfiguration',
                'nodeRegistration': {'kubeletExtraArgs': {'container-runtime-endpoint':
                                                        'unix:///run/containerd/containerd.sock'}}}
        with mock.patch.object(kubernetes, 'get_join_dict', return_value={}), \
                mock.patch.object(components, 'get_init_config', return_value=join), \
                mock.patch.object(kubernetes.utils, 'dump_file'):
            kubernetes.init_workers(group)
        uploaded = yaml.safe_load(group.put.call_args.args[0].getvalue())
        if version == 'v1.37.0':
            self.assertEqual('kubeadm.k8s.io/v1beta4', uploaded['apiVersion'])
            self.assertEqual([{'name': 'container-runtime-endpoint',
                               'value': 'unix:///run/containerd/containerd.sock'}],
                             uploaded['nodeRegistration']['kubeletExtraArgs'])
        else:
            self.assertEqual(join, uploaded)
        self.assertIsInstance(join['nodeRegistration']['kubeletExtraArgs'], dict)

    def test_v1beta4_serialization_preserves_inventory_and_timeouts(self):
        for version in ('v1.33.6', 'v1.36.0', 'v1.37.0'):
            with self.subTest(version=version):
                inventory = demo.generate_inventory(**demo.ALLINONE)
                inventory['services']['kubeadm'] = {
                    'kubernetesVersion': version,
                    'apiVersion': 'kubeadm.k8s.io/v1beta3',
                    'apiServer': {'timeoutForControlPlane': '5m'},
                }
                cluster = demo.new_cluster(inventory)
                before = deepcopy(cluster.inventory)
                init = components.get_init_config(cluster, cluster.nodes['control-plane'], init=True)
                docs = list(yaml.safe_load_all(components.get_kubeadm_config(cluster, init)))
                config = next(doc for doc in docs if doc['kind'] == 'ClusterConfiguration')
                if version != 'v1.37.0':
                    expected = yaml.dump_all(list(components.KubeadmConfig(cluster).maps.values()) + [init])
                    self.assertEqual(expected, components.get_kubeadm_config(cluster, init))
                    self.assertEqual('kubeadm.k8s.io/v1beta3', config['apiVersion'])
                    self.assertEqual('5m', config['apiServer']['timeoutForControlPlane'])
                    self.assertIsInstance(config['apiServer']['extraArgs'], dict)
                    self.assertEqual(before, cluster.inventory)
                    continue
                self.assertEqual('kubeadm.k8s.io/v1beta4', config['apiVersion'])
                for section in ('apiServer', 'scheduler', 'controllerManager'):
                    self.assertIsInstance(config[section]['extraArgs'], list)
                self.assertIsInstance(config['etcd']['local']['extraArgs'], list)
                self.assertNotIn('timeoutForControlPlane', config['apiServer'])
                self.assertEqual('5m', docs[-1]['timeouts']['controlPlaneComponentHealthCheck'])
                self.assertIsInstance(docs[-1]['nodeRegistration']['kubeletExtraArgs'], list)
                self.assertEqual(before, cluster.inventory)

    def test_v1beta4_read_roundtrip_and_duplicate_rejection(self):
        config = {'apiVersion': 'kubeadm.k8s.io/v1beta4', 'kind': 'ClusterConfiguration',
                  'apiServer': {'extraArgs': [{'name': 'custom', 'value': 'true'}]},
                  'customField': {'preserved': True}}
        normalized = components.convert_kubeadm_config(config, to_wire=False)
        self.assertEqual({'custom': 'true'}, normalized['apiServer']['extraArgs'])
        self.assertEqual(config, components.convert_kubeadm_config(normalized, to_wire=True))
        config['apiServer']['extraArgs'].append({'name': 'custom', 'value': 'false'})
        with self.assertRaisesRegex(ValueError, 'Duplicate kubeadm argument'):
            components.convert_kubeadm_config(config, to_wire=False)

    def test_join_timeout_migration(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['kubeadm'] = {'kubernetesVersion': 'v1.37.0'}
        cluster = demo.new_cluster(inventory)
        join = {'apiVersion': 'kubeadm.k8s.io/v1beta3', 'kind': 'JoinConfiguration',
                'discovery': {'timeout': '3m'}, 'nodeRegistration': {'kubeletExtraArgs': {}}}
        result = list(yaml.safe_load_all(components.get_kubeadm_config(cluster, join)))[-1]
        self.assertEqual({'discovery': '3m'}, result['timeouts'])
        self.assertNotIn('timeout', result['discovery'])

    def test_load_and_edit_existing_kubeadm_config(self):
        self._check_load_and_edit_existing_kubeadm_config('v1.37.0')

    def test_load_and_edit_preserves_api_for_older_versions(self):
        self._check_load_and_edit_existing_kubeadm_config('v1.36.0')

    def _check_load_and_edit_existing_kubeadm_config(self, target_version):
        for api_version in ('v1beta3', 'v1beta4'):
            with self.subTest(api_version=api_version):
                inventory = demo.generate_inventory(**demo.ALLINONE)
                inventory['services']['kubeadm'] = {'kubernetesVersion': target_version}
                cluster = demo.new_cluster(inventory)
                control_plane = cluster.nodes['control-plane'].get_first_member()
                config = {'kind': 'ClusterConfiguration',
                          'apiVersion': f'kubeadm.k8s.io/{api_version}',
                          'kubernetesVersion': 'v1.36.0',
                          'apiServer': {'extraArgs': {'custom': 'old'}}}
                if api_version == 'v1beta4':
                    config = components.convert_kubeadm_config(config, to_wire=True)
                data = {'data': {'ClusterConfiguration': yaml.dump(config)}}
                cluster.fake_shell.add(
                    demo.create_hosts_result([control_plane.get_host()], stdout=json.dumps(data)),
                    'sudo', ['kubectl get configmap -n kube-system kubeadm-config -o json'])

                def edit(value):
                    args = value['apiServer']['extraArgs']
                    if isinstance(args, list):
                        args[0]['value'] = 'new'
                    else:
                        args['custom'] = 'new'
                    return value

                kubeadm = components.KubeadmConfig(cluster)
                loaded = kubeadm.load('kubeadm-config', control_plane, edit)
                use_v1beta4 = target_version == 'v1.37.0'
                expected_args = [{'name': 'custom', 'value': 'new'}]
                self.assertEqual({'custom': 'new'} if use_v1beta4 or api_version == 'v1beta3' else expected_args,
                                 loaded['apiServer']['extraArgs'])
                wire = yaml.safe_load(kubeadm.loaded_maps['kubeadm-config'].obj['data']['ClusterConfiguration'])
                self.assertEqual('v1.36.0', wire['kubernetesVersion'])
                self.assertEqual('kubeadm.k8s.io/v1beta4' if use_v1beta4 else f'kubeadm.k8s.io/{api_version}',
                                 wire['apiVersion'])
                self.assertEqual(expected_args if use_v1beta4 or api_version == 'v1beta4' else {'custom': 'new'},
                                 wire['apiServer']['extraArgs'])

    def test_get_init_config_control_plane(self):
        inventory = demo.generate_inventory(control_plane=1, worker=1, balancer=0)
        cluster = demo.new_cluster(inventory)
        control_plane = cluster.nodes['control-plane'].get_first_member()
        init_config = components.get_init_config(cluster, control_plane, init=True)

        self.assertEqual({'advertiseAddress': inventory['nodes'][0]['internal_address']},
                         init_config.get('localAPIEndpoint'))

        self.assertEqual(None, init_config.get('nodeRegistration', {}).get('taints'))

        self.assertNotIn('discovery', init_config)

    def test_get_init_config_combined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        cluster = demo.new_cluster(inventory)
        control_plane = cluster.nodes['control-plane'].get_first_member()
        init_config = components.get_init_config(cluster, control_plane, init=True)

        self.assertEqual({'advertiseAddress': inventory['nodes'][0]['internal_address']},
                         init_config.get('localAPIEndpoint'))

        self.assertEqual([], init_config.get('nodeRegistration', {}).get('taints'))

        self.assertNotIn('discovery', init_config)

    def test_get_join_config_control_plane(self):
        inventory = demo.generate_inventory(control_plane=1, worker=1, balancer=0)
        cluster = demo.new_cluster(inventory)
        control_plane = cluster.nodes['control-plane'].get_first_member()
        join_config = components.get_init_config(cluster, control_plane, init=False, join_dict={
            'certificate-key': '01233456789abcdef',
            'token': 'abc.xyz',
            'discovery-token-ca-cert-hash': 'sha256:01233456789abcdef',
        })

        self.assertEqual({
            'localAPIEndpoint': {'advertiseAddress': inventory['nodes'][0]['internal_address']},
            'certificateKey': '01233456789abcdef'
        }, join_config.get('controlPlane'))
        self.assertEqual(None, join_config.get('nodeRegistration', {}).get('taints'))

        self.assertIn('bootstrapToken', join_config.get('discovery', {}))

    def test_get_init_config_worker_group(self):
        inventory = demo.generate_inventory(control_plane=1, worker=2, balancer=0)
        cluster = demo.new_cluster(inventory)
        workers = cluster.nodes['worker']
        init_config = components.get_init_config(cluster, workers, init=True)

        self.assertEqual(None, init_config.get('localAPIEndpoint'))
        self.assertEqual(None, init_config.get('nodeRegistration', {}).get('taints'))

    def test_merge_with_inventory(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['kubeadm_kube-proxy'] = {
            'nested': {'property': 'new'},
            'array': [2]
        }
        cluster = demo.new_cluster(inventory)

        control_plane_host = inventory['nodes'][0]['address']
        data = {'data': {'config.conf': yaml.dump({
            'kind': 'KubeProxyConfiguration',
            'nested': {'untouched': True, 'property': 'old'},
            'array': [1]
        })}}
        results = demo.create_hosts_result([control_plane_host], stdout=json.dumps(data))
        cmd = f'kubectl get configmap -n kube-system kube-proxy -o json'
        cluster.fake_shell.add(results, 'sudo', [cmd])

        control_plane = cluster.make_group([control_plane_host])

        kubeadm_config = components.KubeadmConfig(cluster)
        kubeadm_config.load('kube-proxy', control_plane, kubeadm_config.merge_with_inventory('kube-proxy'))

        self._test_merge_with_inventory(kubeadm_config.maps['kube-proxy'])
        self._test_merge_with_inventory(
            yaml.safe_load(kubeadm_config.loaded_maps['kube-proxy'].obj['data']['config.conf']))

        kubeadm_config = components.KubeadmConfig(cluster)
        loaded_config = kubeadm_config.load('kube-proxy', control_plane)
        self.assertEqual('old', loaded_config.get('nested', {}).get('property'))
        self.assertEqual(True, loaded_config.get('nested', {}).get('untouched'))
        self.assertEqual([1], loaded_config.get('array'))

        merged_config = kubeadm_config.merge_with_inventory('kube-proxy')(deepcopy(loaded_config))
        self._test_merge_with_inventory(merged_config)

    def _test_merge_with_inventory(self, config: dict):
        self.assertEqual('new', config.get('nested', {}).get('property'))
        self.assertEqual(True, config.get('nested', {}).get('untouched'))
        self.assertEqual([2], config.get('array'))

    def test_kubelet_local_mode_enrichment(self):
        # Enriched featureGates.ControlPlaneKubeletLocalMode=true for kubernetes 1.31+
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.33.6'
        cluster = demo.new_cluster(inventory)
        kubeadm = cluster.inventory['services']['kubeadm']
        self.assertIsNotNone(kubeadm.get('featureGates'))
        self.assertTrue(kubeadm['featureGates'].get('ControlPlaneKubeletLocalMode'))

        # Enriched featureGates.ControlPlaneKubeletLocalMode=true for kubernetes 1.31+ with not empty featureGates
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.33.6'
        inventory['services'].setdefault('kubeadm', {}).setdefault('featureGates', {})['foo'] = 'bar'
        cluster = demo.new_cluster(inventory)
        kubeadm = cluster.inventory['services']['kubeadm']
        self.assertIsNotNone(kubeadm.get('featureGates'))
        self.assertEqual('bar', kubeadm['featureGates'].get('foo'))
        self.assertTrue(kubeadm['featureGates'].get('ControlPlaneKubeletLocalMode'))

        # Do not change featureGates.ControlPlaneKubeletLocalMode=true for kubernetes 1.31+ if value is overridden
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.33.6'
        inventory['services'].setdefault('kubeadm', {}).setdefault('featureGates', {})['ControlPlaneKubeletLocalMode'] = False
        cluster = demo.new_cluster(inventory)
        kubeadm = cluster.inventory['services']['kubeadm']
        self.assertIsNotNone(kubeadm.get('featureGates'))
        self.assertFalse(kubeadm['featureGates'].get('ControlPlaneKubeletLocalMode'))

class WaitForPodsTest(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        random.shuffle(self.inventory['nodes'])

        self.inventory.setdefault('globals', {}).setdefault('expect', {}).setdefault('pods', {})['kubernetes'] = {
            'timeout': 0, 'retries': 3
        }

    def _new_cluster(self) -> demo.FakeKubernetesCluster:
        return demo.new_cluster(self.inventory)

    def _stub_get_pods(self, cluster: demo.FakeKubernetesCluster, hosts: List[str], pods: List[str], node_name: str,
                       *, ready: bool = True):
        internal_address = cluster.get_node_by_name(node_name)['internal_address']
        ready_string = '1/1' if ready else '0/1'
        output = '\n'.join((
            # pylint: disable-next=line-too-long
            f'{pod}            {ready_string}     Running   0          1s   {internal_address}   {node_name}   <none>           <none>'
            for pod in pods
        ))
        results = demo.create_hosts_result(hosts, stdout=output)
        cmd = f'kubectl get pods -n kube-system -o=wide | grep {node_name}'
        cluster.fake_shell.add(results, 'sudo', [cmd])

    def test_wait_empty(self):
        cluster = self._new_cluster()
        components.wait_for_pods(cluster.nodes['all'], [])

    def test_wait_not_supported(self):
        cluster = self._new_cluster()
        with self.assertRaisesRegex(Exception, re.escape(components.ERROR_WAIT_FOR_PODS_NOT_SUPPORTED.format(
                components=['kube-apiserver/cert-sans', 'kubelet', 'unexpected-component']))):
            components.wait_for_pods(cluster.nodes['all'].get_any_member(), components.ALL_COMPONENTS + ['unexpected-component'])

    def test_wait_workers_successful(self):
        cluster = self._new_cluster()
        first_control_plane = next(node for node in self.inventory['nodes'] if 'control-plane' in node['roles'])['address']
        for node in self.inventory['nodes']:
            if 'worker' in node['roles']:
                self._stub_get_pods(cluster, [first_control_plane], ['calico-node-abc12', 'kube-proxy-34xyz'], node['name'])

        components.wait_for_pods(cluster.nodes['worker'])

    def test_wait_worker_failed(self):
        cluster = self._new_cluster()
        first_control_plane = next(node for node in self.inventory['nodes'] if 'control-plane' in node['roles'])['address']
        for node in self.inventory['nodes']:
            if 'worker' in node['roles']:
                self._stub_get_pods(cluster, [first_control_plane], ['calico-node-abc12', 'kube-proxy-34xyz'],
                                    node['name'], ready=False)

        with self.assertRaisesRegex(Exception, re.escape(plugins.ERROR_PODS_NOT_READY)):
            components.wait_for_pods(cluster.nodes['worker'].get_any_member())

    def test_wait_control_planes_successful(self):
        cluster = self._new_cluster()
        for node in self.inventory['nodes']:
            if 'control-plane' in node['roles']:
                self._stub_get_pods(cluster, [node['address']], [
                    "calico-node-abc12", f"etcd-{node['name']}",
                    f"kube-apiserver-{node['name']}", f"kube-controller-manager-{node['name']}",
                    "kube-proxy-34xyz", f"kube-scheduler-{node['name']}",
                ], node['name'])

        components.wait_for_pods(cluster.nodes['control-plane'])

    def test_wait_control_plane_failed(self):
        cluster = self._new_cluster()
        for node in self.inventory['nodes']:
            if 'control-plane' in node['roles']:
                self._stub_get_pods(cluster, [node['address']], [
                    "calico-node-abc12",  # f"etcd-{node['name']}",
                    f"kube-apiserver-{node['name']}", f"kube-controller-manager-{node['name']}",
                    "kube-proxy-34xyz", f"kube-scheduler-{node['name']}",
                ], node['name'])

        with self.assertRaisesRegex(Exception, re.escape(plugins.ERROR_PODS_NOT_READY)):
            components.wait_for_pods(cluster.nodes['control-plane'].get_any_member())

    def test_wait_specific(self):
        cluster = self._new_cluster()
        for node in self.inventory['nodes']:
            if 'control-plane' in node['roles']:
                self._stub_get_pods(cluster, [node['address']], [
                    "calico-node-abc12", f"etcd-{node['name']}",
                    f"kube-apiserver-{node['name']}", f"kube-controller-manager-{node['name']}",
                    "kube-proxy-34xyz", f"kube-scheduler-{node['name']}",
                ], node['name'])

        with test_utils.mock_call(plugins.expect_pods) as run:
            components.wait_for_pods(cluster.nodes['all'], ['kube-apiserver'])
            node_names = {call[1]['node_name'] for call in run.call_args_list}
            self.assertEqual({'control-plane-1', 'control-plane-2', 'control-plane-3'}, node_names)

        with test_utils.mock_call(plugins.expect_pods) as run:
            components.wait_for_pods(cluster.nodes['all'], ['kube-proxy'])
            node_names = {call[1]['node_name'] for call in run.call_args_list}
            self.assertEqual({'control-plane-1', 'control-plane-2', 'control-plane-3', 'worker-1', 'worker-2', 'worker-3'},
                             node_names)


class RestartComponentsTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        random.shuffle(self.inventory['nodes'])

    def _new_cluster(self) -> demo.FakeKubernetesCluster:
        return demo.new_cluster(self.inventory)

    def test_restart_empty(self):
        cluster = self._new_cluster()
        components.restart_components(cluster.nodes['all'], [])

    def test_restart_not_supported(self):
        cluster = self._new_cluster()
        with self.assertRaisesRegex(Exception, re.escape(components.ERROR_RESTART_NOT_SUPPORTED.format(
                components=['kube-apiserver/cert-sans', 'kubelet', 'kube-proxy', 'unexpected-component']))):
            components.restart_components(cluster.nodes['all'].get_any_member(),
                                          components.ALL_COMPONENTS + ['unexpected-component'])

    def test_restart_all_supported(self):
        cluster = self._new_cluster()
        with test_utils.mock_call(components._restart_containers) as restart_containers, \
                test_utils.mock_call(plugins.expect_pods) as expect_pods:

            all_components = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd']
            components.restart_components(cluster.nodes['all'], all_components)

            control_plane_components = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd']
            expected_control_planes = [node['name'] for node in self.inventory['nodes'] if 'control-plane' in node['roles']]

            restart_containers_expected_calls = [(node, control_plane_components) for node in expected_control_planes]
            restart_containers_actual_calls = [(call[0][1].get_node_name(), list(call[0][2]))
                                               for call in restart_containers.call_args_list
                                               if call[0][2]]
            self.assertEqual(restart_containers_expected_calls, restart_containers_actual_calls)

            actual_called_nodes = [call[1]['node_name'] for call in expect_pods.call_args_list]
            self.assertEqual(expected_control_planes, actual_called_nodes)

            for call in expect_pods.call_args_list:
                self.assertEqual(control_plane_components, call[0][1])

    def test_restart_specific(self):
        cluster = self._new_cluster()
        with test_utils.mock_call(components._restart_containers) as restart_containers, \
                test_utils.mock_call(plugins.expect_pods) as expect_pods:

            components.restart_components(cluster.nodes['control-plane'].get_first_member(), [
                'kube-apiserver'
            ])

            first_control_plane = next(node for node in self.inventory['nodes'] if 'control-plane' in node['roles'])

            self.assertEqual(1, restart_containers.call_count)
            self.assertEqual(first_control_plane['name'], restart_containers.call_args[0][1].get_node_name())
            self.assertEqual(['kube-apiserver'], list(restart_containers.call_args[0][2]))

            self.assertEqual(1, expect_pods.call_count)
            self.assertEqual(first_control_plane['name'], expect_pods.call_args[1]['node_name'])
            self.assertEqual(['kube-apiserver'], expect_pods.call_args[0][1])


class ReconfigureComponentsTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        random.shuffle(self.inventory['nodes'])
        self.control_planes = [node['name'] for node in self.inventory['nodes'] if 'control-plane' in node['roles']]
        self.workers = [node['name'] for node in self.inventory['nodes'] if 'worker' in node['roles']]

        self.control_plane_components = ['kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd']

    def _new_cluster(self) -> demo.FakeKubernetesCluster:
        return demo.new_cluster(self.inventory)

    def test_reconfigure_empty(self):
        cluster = self._new_cluster()
        components.reconfigure_components(cluster.nodes['all'], [])

    def test_reconfigure_not_supported(self):
        cluster = self._new_cluster()
        with self.assertRaisesRegex(Exception, re.escape(components.ERROR_RECONFIGURE_NOT_SUPPORTED.format(
                components=['unexpected-component']))):
            components.reconfigure_components(cluster.nodes['all'].get_any_member(),
                                              components.ALL_COMPONENTS + ['unexpected-component'])

    def test_reconfigure_all_supported(self):
        for changes_detected, force_restart in (
                ([], False),
                (['control-planes'], False),
                (['kubelet'], False),
                (['kube-proxy'], False),
                (['control-planes', 'kubelet', 'kube-proxy'], False),
                ([], True)
        ):
            with self.subTest(f"Changes detected: {changes_detected}, force restart: {force_restart}"):
                self._test_reconfigure_all_supported(changes_detected, force_restart)

    def _test_reconfigure_all_supported(self, changes_detected: List[str], force_restart: bool):
        cluster = self._new_cluster()
        with test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                self._test_reconfigure_apiserver_certsans(), \
                self._test_reconfigure_control_plane('control-planes' in changes_detected, self.control_plane_components), \
                self._test_reconfigure_kubelet('kubelet' in changes_detected), \
                test_utils.mock_call(components._update_configmap,
                                     return_value='kube-proxy' in changes_detected), \
                self._test_restart_kubelet('kubelet' in changes_detected or force_restart), \
                self._test_delete_kube_proxy_pods(force_restart or set(changes_detected) & {'kube-proxy', 'kubelet'}), \
                self._test_restart_containers(self.control_plane_components, True,
                                              'control-planes' in changes_detected or force_restart,
                                              'kubelet' in changes_detected or force_restart), \
                self._test_wait_for_pods(self.control_plane_components, True, True):

            components.reconfigure_components(cluster.nodes['all'], components.ALL_COMPONENTS,
                                              force_restart=force_restart)

    def test_reconfigure_apiserver_certsans(self):
        cluster = self._new_cluster()
        with test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                self._test_reconfigure_apiserver_certsans(), \
                test_utils.mock_call(components._update_configmap, return_value=False), \
                self._test_restart_containers([], True, False, False), \
                self._test_wait_for_pods(['kube-apiserver'], False, False):

            components.reconfigure_components(cluster.nodes['all'], ['kube-apiserver/cert-sans'])

    def test_reconfigure_control_planes_specific(self):
        for changes_detected, force_restart in (
                (True, False),
                (False, False),
                (False, True)
        ):
            with self.subTest(f"Changes detected: {changes_detected}, force restart: {force_restart}"), \
                    test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                    self._test_reconfigure_control_plane(changes_detected, ['etcd']), \
                    test_utils.mock_call(components._update_configmap, return_value=changes_detected), \
                    self._test_restart_containers(['etcd'], False,
                                                  changes_detected or force_restart, False), \
                    self._test_wait_for_pods(['etcd'], False, False):

                cluster = self._new_cluster()
                components.reconfigure_components(cluster.nodes['all'], ['etcd'],
                                                  force_restart=force_restart)

    def test_reconfigure_kubelet(self):
        for changes_detected, force_restart in (
                (True, False),
                (False, False),
                (False, True)
        ):
            with self.subTest(f"Changes detected: {changes_detected}, force restart: {force_restart}"), \
                    test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                    self._test_reconfigure_kubelet(changes_detected), \
                    test_utils.mock_call(components._update_configmap, return_value=changes_detected), \
                    self._test_restart_kubelet(changes_detected or force_restart), \
                    self._test_delete_kube_proxy_pods(force_restart or changes_detected), \
                    self._test_restart_containers([], False,
                                                  False, changes_detected or force_restart), \
                    self._test_wait_for_pods([], True, False):

                cluster = self._new_cluster()
                components.reconfigure_components(cluster.nodes['all'], ['kubelet'],
                                                  force_restart=force_restart)

    def test_reconfigure_kube_proxy(self):
        for changes_detected, force_restart in (
                (True, False),
                (False, False),
                (False, True)
        ):
            with self.subTest(f"Changes detected: {changes_detected}, force restart: {force_restart}"), \
                    test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                    test_utils.mock_call(components._update_configmap, return_value=changes_detected), \
                    self._test_delete_kube_proxy_pods(force_restart or changes_detected), \
                    self._test_wait_for_pods([], False, True):

                cluster = self._new_cluster()
                components.reconfigure_components(cluster.nodes['all'], ['kube-proxy'],
                                                  force_restart=force_restart)

    @contextmanager
    def _test_reconfigure_apiserver_certsans(self):
        with test_utils.mock_call(components._reconfigure_apiserver_certsans) as mock:
            yield
        actual_calls = [call[0][0].get_node_name() for call in mock.call_args_list]
        self.assertEqual(self.control_planes, actual_calls)

    @contextmanager
    def _test_reconfigure_control_plane(self, changes_detected: bool, components_: List[str]):
        with test_utils.mock_call(components._reconfigure_control_plane_component, return_value=changes_detected) as mock:
            yield

        expected_calls = [(node, component) for node in self.control_planes for component in components_]
        actual_calls = [(call[0][1].get_node_name(), call[0][2]) for call in mock.call_args_list]
        self.assertEqual(expected_calls, actual_calls)

    @contextmanager
    def _test_reconfigure_kubelet(self, changes_detected: bool):
        with test_utils.mock_call(components._reconfigure_kubelet, return_value=changes_detected) as mock:
            yield

        actual_calls = [call[0][1].get_node_name() for call in mock.call_args_list]
        self.assertEqual(self.control_planes + self.workers, actual_calls)

    @contextmanager
    def _test_restart_kubelet(self, should_restart: bool):
        with test_utils.mock_call(system.restart_service) as mock:
            yield

        expected_calls = ((self.control_planes + self.workers) if should_restart else [])
        actual_calls = [call[0][0].get_node_name() for call in mock.call_args_list]
        self.assertEqual(expected_calls, actual_calls)

    @contextmanager
    def _test_delete_kube_proxy_pods(self, should_delete: bool):
        with test_utils.mock_call(components._delete_pods) as mock:
            yield

        expected_calls = [(node, 'kube-proxy') for node in (self.control_planes + self.workers)
                          if should_delete]
        actual_calls = [(call[0][1].get_node_name(), component)
                        for call in mock.call_args_list
                        for component in call[0][3]]
        self.assertEqual(expected_calls, actual_calls)

    @contextmanager
    def _test_restart_containers(self, control_plane_components: List[str],
                                 configure_certsans: bool, components_restart: bool, kubelet_restart: bool):
        with test_utils.mock_call(components._restart_containers) as mock:
            yield

        expected_calls = []
        for node in self.control_planes:
            expected_components = []
            if configure_certsans:
                # It is currently not possible to detect changes in cert SANs, so kube-apiserver is restarted anyway.
                expected_components = ['kube-apiserver']
            if components_restart:
                expected_components = list(OrderedSet(expected_components + control_plane_components))

            if expected_components:
                expected_calls.append((node, expected_components))

            if kubelet_restart:
                expected_calls.append((node, self.control_plane_components))

        actual_calls = [(call[0][1].get_node_name(), list(call[0][2]))
                        for call in mock.call_args_list
                        if call[0][2]]

        self.assertEqual(expected_calls, actual_calls)

    @contextmanager
    def _test_wait_for_pods(self, control_plane_components: List[str],
                            reconfigure_kubelet: bool, reconfigure_kube_proxy):
        with test_utils.mock_call(plugins.expect_pods) as mock:
            yield

        expected_calls = []
        for node in self.control_planes:
            if control_plane_components:
                expected_calls.append((node, control_plane_components))
            if reconfigure_kubelet:
                expected_calls.append((node, ['kube-proxy'] + self.control_plane_components))
            elif reconfigure_kube_proxy:
                expected_calls.append((node, ['kube-proxy']))

        expected_calls.extend((node, ['kube-proxy']) for node in self.workers if reconfigure_kubelet or reconfigure_kube_proxy)
        actual_calls = [(call[1]['node_name'], call[0][1]) for call in mock.call_args_list]
        self.assertEqual(expected_calls, actual_calls)


if __name__ == '__main__':
    unittest.main()
