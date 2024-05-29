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
from typing import List
from test.unit import utils as test_utils

import yaml
from ordered_set import OrderedSet

from kubemarine import demo, plugins, system
from kubemarine.kubernetes import components


class KubeadmConfigTest(unittest.TestCase):
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
