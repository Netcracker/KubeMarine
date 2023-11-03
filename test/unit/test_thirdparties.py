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
from kubemarine import demo, thirdparties
from kubemarine.core import errors


class EnrichmentValidation(unittest.TestCase):
    def test_missed_source(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'] = {'thirdparties': {
            '/custom/path': {}}
        }
        with self.assertRaisesRegex(errors.FailException, r"'source' is a required property"):
            demo.new_cluster(inventory)


class SHACalculationTest(unittest.TestCase):

    customized_services = {
        'kubeadm': {
            'kubernetesVersion': "v1.24.2"
        },
        'thirdparties': {
            '/usr/bin/kubelet': {
                'source': 'overriden_source'
            },
            '/usr/bin/kubectl': {
                'source': 'overriden_source',
                'sha1': 'overriden_sha'
            },
            'custom/thirdparty/without/sha': {
                'source': 'some-source'
            },
            'custom/thirdparty/with/sha': {
                'source': 'some-source',
                'sha1': 'some-sha'
            }
        }
    }

    def test_recommended_sha_calculation(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)

        # Add custom parameters with version and override thirdparties info
        inventory['services'] = self.customized_services

        cluster = demo.new_cluster(inventory, fake=False)

        self.assertIsNone(thirdparties.get_thirdparty_recommended_sha("/usr/bin/etcdctl", cluster))
        self.assertEqual(cluster.globals['compatibility_map']['software']['kubeadm']['v1.24.2']['sha1'],
                         thirdparties.get_thirdparty_recommended_sha("/usr/bin/kubeadm", cluster))
        self.assertEqual(cluster.globals['compatibility_map']['software']['kubelet']['v1.24.2']['sha1'],
                         thirdparties.get_thirdparty_recommended_sha("/usr/bin/kubelet", cluster))
        self.assertEqual(cluster.globals['compatibility_map']['software']['kubectl']['v1.24.2']['sha1'],
                         thirdparties.get_thirdparty_recommended_sha("/usr/bin/kubectl", cluster))
        self.assertEqual(cluster.globals['compatibility_map']['software']['calicoctl']['v1.24.2']['sha1'],
                         thirdparties.get_thirdparty_recommended_sha("/usr/bin/calicoctl", cluster))
        self.assertIsNone(thirdparties.get_thirdparty_recommended_sha("custom/thirdparty/without/sha", cluster))
        self.assertIsNone(thirdparties.get_thirdparty_recommended_sha("custom/thirdparty/with/sha", cluster))

    def test_default_sha_calculation(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)

        # Add custom parameters with version and override thirdparties info
        inventory['services'] = self.customized_services

        cluster = demo.new_cluster(inventory, fake=False)

        self.assertNotIn('sha1', cluster.inventory['services']['thirdparties']["/usr/bin/etcdctl"])
        self.assertEqual(cluster.globals['compatibility_map']['software']['kubeadm']['v1.24.2']['sha1'],
                         cluster.inventory['services']['thirdparties']["/usr/bin/kubeadm"]['sha1'])
        self.assertNotIn('sha1', cluster.inventory['services']['thirdparties']["/usr/bin/kubelet"])
        self.assertEqual(self.customized_services['thirdparties']['/usr/bin/kubectl']['sha1'],
                         cluster.inventory['services']['thirdparties']["/usr/bin/kubectl"]['sha1'])
        self.assertEqual(cluster.globals['compatibility_map']['software']['calicoctl']['v1.24.2']['sha1'],
                         cluster.inventory['services']['thirdparties']["/usr/bin/calicoctl"]['sha1'])
        self.assertNotIn('sha1', cluster.inventory['services']['thirdparties']["custom/thirdparty/without/sha"])
        self.assertEqual(self.customized_services['thirdparties']['custom/thirdparty/with/sha']['sha1'],
                         cluster.inventory['services']['thirdparties']["custom/thirdparty/with/sha"]['sha1'])


if __name__ == '__main__':
    unittest.main()
