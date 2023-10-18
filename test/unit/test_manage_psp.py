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


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': 'psp',
            'psp': {
                'pod-security': 'enabled'
            }
        }
        self.context = demo.create_silent_context(['fake.yaml'], procedure='manage_psp')
        self.manage_psp = demo.generate_procedure_inventory('manage_psp')
        self.manage_psp['psp']['pod-security'] = 'enabled'

    def _create_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.manage_psp),
                                context=self.context)

    def test_missed_psp(self):
        del self.manage_psp['psp']
        with self.assertRaisesRegex(errors.FailException, r"'psp' is a required property"):
            self._create_cluster()

    def test_unexpected_pod_security(self):
        self.manage_psp['psp']['pod-security'] = 'unexpected'
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
            self._create_cluster()

    def test_unexpected_oob_policy_flag(self):
        self.manage_psp['psp']['oob-policies'] = {'default': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
            self._create_cluster()

    def test_custom_policies_not_allowed(self):
        self.manage_psp['psp']['custom-policies'] = {}
        with self.assertRaisesRegex(errors.FailException, r"'custom-policies' was unexpected"):
            self._create_cluster()

    def test_custom_psp_list_unexpected_kind(self):
        for custom_policy_op in ('add-policies', 'delete-policies'):
            self.manage_psp['psp'][custom_policy_op] = {'psp-list': [self._stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['PodSecurityPolicy']"):
                self._create_cluster()

    def test_custom_roles_list_unexpected_kind(self):
        for custom_policy_op in ('add-policies', 'delete-policies'):
            self.manage_psp['psp'][custom_policy_op] = {'roles-list': [self._stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['Role', 'ClusterRole']"):
                self._create_cluster()

    def test_custom_bindings_list_unexpected_kind(self):
        for custom_policy_op in ('add-policies', 'delete-policies'):
            self.manage_psp['psp'][custom_policy_op] = {'bindings-list': [self._stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['RoleBinding', 'ClusterRoleBinding']"):
                self._create_cluster()

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
