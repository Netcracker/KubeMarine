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
from test.unit import utils


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': 'pss',
            'pss': {
                'pod-security': 'enabled'
            }
        }
        self.context = demo.create_silent_context(['fake.yaml'], procedure='manage_pss')
        self.manage_pss = demo.generate_procedure_inventory('manage_pss')
        self.manage_pss['pss'].update({
            'defaults': {},
            'namespaces': [],
            'namespaces_defaults': {}
        })

    def _create_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.manage_pss),
                                context=self.context)

    def test_missed_pss(self):
        del self.manage_pss['pss']
        with self.assertRaisesRegex(errors.FailException, r"'pss' is a required property"):
            self._create_cluster()

    def test_missed_pss_pod_security(self):
        del self.manage_pss['pss']['pod-security']
        with self.assertRaisesRegex(errors.FailException, r"'pod-security' is a required property"):
            self._create_cluster()

    def test_unexpected_pod_security(self):
        self.manage_pss['pss']['pod-security'] = 'unexpected'
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['enabled', 'disabled']"):
            self._create_cluster()

    def test_invalid_defaults_profile(self):
        self.manage_pss['pss']['defaults']['enforce'] = 'unexpected'
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['privileged', 'baseline', 'restricted']"):
            self._create_cluster()

    def test_invalid_namespaces_profile(self):
        self.manage_pss['pss']['namespaces'] = [
            {'custom_ns': {'enforce': 'unexpected'}}
        ]
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['privileged', 'baseline', 'restricted']"):
            self._create_cluster()

    def test_invalid_namespaces_defaults_profile(self):
        self.manage_pss['pss']['namespaces_defaults'] = {'enforce': 'unexpected'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['privileged', 'baseline', 'restricted']"):
            self._create_cluster()


class EnrichmentAndFinalization(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.MINIHA)
        self.inventory['rbac'] = {
            "admission": "pss",
            "pss": {
                "pod-security": "enabled",
                "exemptions": {
                    "namespaces": []
                }
            }
        }
        self.context = demo.create_silent_context(['fake.yaml'], procedure='manage_pss')
        self.manage_pss = demo.generate_procedure_inventory('manage_pss')
        self.manage_pss['pss']['exemptions'] = {
            "namespaces": []
        }

    def _create_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.manage_pss),
                                context=self.context)

    def test_merge_exemptions(self):
        self.inventory['rbac']['pss']['exemptions']['namespaces'] = ['a', 'b']
        self.manage_pss['pss']['exemptions']['namespaces'] = [{'<<': 'merge'}, 'c']

        cluster = self._create_cluster()
        self.assertEqual(['a', 'b', 'c'], cluster.inventory['rbac']['pss']['exemptions']['namespaces'])

        utils.stub_associations_packages(cluster, {})
        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(['a', 'b', 'c'], finalized_inventory['rbac']['pss']['exemptions']['namespaces'])

        final_inventory = utils.get_final_inventory(cluster, self.inventory)
        self.assertEqual(['a', 'b', 'c'], final_inventory['rbac']['pss']['exemptions']['namespaces'])


if __name__ == '__main__':
    unittest.main()
