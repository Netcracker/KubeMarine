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
from copy import deepcopy

from kubemarine import demo
from kubemarine.core import errors
from test.unit import EnvSetup


class EnrichmentValidation(EnvSetup):
    def _inventory(self, admission):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': admission,
            admission: {
                'pod-security': 'enabled'
            }
        }
        return self.inventory['rbac'][admission]

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory))

    def test_unexpected_admission(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['rbac'] = {
            'admission': 'unexpected'
        }
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['psp', 'pss']"):
            demo.new_cluster(inventory)

    def test_unexpected_pod_security(self):
        for admission in ('psp', 'pss'):
            self._inventory(admission)['pod-security'] = 'unexpected'
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
                self._new_cluster()

    def test_pss_invalid_profile(self):
        self._inventory('pss')['defaults'] = {'enforce': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['privileged', 'baseline', 'restricted']"):
            self._new_cluster()

    def test_psp_unexpected_oob_policy_flag(self):
        self._inventory('psp')['oob-policies'] = {'default': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
            self._new_cluster()

    def test_psp_custom_psp_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'psp-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['PodSecurityPolicy']"):
            self._new_cluster()

    def test_psp_custom_roles_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'roles-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['Role', 'ClusterRole']"):
            self._new_cluster()

    def test_psp_custom_bindings_list_unexpected_kind(self):
        self._inventory('psp')['custom-policies'] = {'bindings-list': [self._stub_resource('Unexpected')]}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['RoleBinding', 'ClusterRoleBinding']"):
            self._new_cluster()

    def test_default_admission_for_kuber_version(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)

        # Old kuber version with default psp admission
        inventory['services']['kubeadm'] = {'kubernetesVersion': 'v1.24.11'}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory['rbac']['admission'], 'psp')

        # New kuber version with default pss admission
        inventory['services']['kubeadm'] = {'kubernetesVersion': 'v1.25.2'}
        cluster = demo.new_cluster(inventory)
        self.assertEqual(cluster.inventory['rbac']['admission'], 'pss')

    def _stub_resource(self, kind):
        return {
            'apiVersion': 'policy/v1beta1',
            'kind': kind,
            'metadata': {
                'name': 'custom'
            }
        }


if __name__ == '__main__':
    unittest.main()
