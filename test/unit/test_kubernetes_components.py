import json
import unittest
from copy import deepcopy

import yaml

from kubemarine import demo
from kubemarine.kubernetes import components


class KubeadmConfigTest(unittest.TestCase):
    def test_get_init_config_control_plane(self):
        inventory = demo.generate_inventory(master=1, worker=1, balancer=0)
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
        inventory = demo.generate_inventory(master=1, worker=1, balancer=0)
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
        inventory = demo.generate_inventory(master=1, worker=2, balancer=0)
        cluster = demo.new_cluster(inventory)
        workers = cluster.nodes['worker']
        init_config = components.get_init_config(cluster, workers, init=True)

        self.assertEqual(None, init_config.get('localAPIEndpoint'))
        self.assertEqual(None, init_config.get('nodeRegistration', {}).get('taints'))

    def test_merge_with_inventory(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        fake_shell = demo.FakeShell()

        control_plane_host = inventory['nodes'][0]['address']
        data = {'data': {'config.conf': yaml.dump({
            'kind': 'KubeProxyConfiguration',
            'nested': {'untouched': True, 'property': 'old'},
            'array': [1]
        })}}
        results = demo.create_hosts_result([control_plane_host], stdout=json.dumps(data))
        cmd = f'kubectl get configmap -n kube-system kube-proxy -o json'
        fake_shell.add(results, 'sudo', [cmd])

        inventory['services']['kubeadm_kube-proxy'] = {
            'nested': {'property': 'new'},
            'array': [2]
        }

        context = demo.create_silent_context()
        nodes_context = demo.generate_nodes_context(inventory)
        res = demo.FakeResources(context, inventory, nodes_context=nodes_context, fake_shell=fake_shell)
        cluster = res.cluster()

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


if __name__ == '__main__':
    unittest.main()
