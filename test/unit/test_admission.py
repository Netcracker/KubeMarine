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
import re
import unittest
from copy import deepcopy
from test.unit import utils as test_utils

from kubemarine import demo
from kubemarine.core import errors


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)

    def _inventory(self, admission):
        self.inventory['rbac'] = {
            'admission': admission,
            admission: {
                'pod-security': 'enabled'
            }
        }
        if admission == 'psp':
            self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.24.11'

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

    def test_pss_defaults_verify_version(self):
        self._inventory('pss')['defaults'] = {'enforce-version': 'not a version'}
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.30.1'
        with self.assertRaisesRegex(Exception, re.escape(
                f"Incorrect enforce-version 'not a version', "
                f"valid version (for example): v1.30")):
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

    def test_pss_remove_psp(self):
        self._inventory('pss')
        cluster = self._new_cluster()
        self.assertNotIn('psp', cluster.inventory['rbac'])
        self.assertNotIn('psp', test_utils.make_finalized_inventory(cluster)['rbac'])

    def test_psp_remove_pss(self):
        self._inventory('psp')
        cluster = self._new_cluster()
        self.assertNotIn('pss', cluster.inventory['rbac'])
        self.assertNotIn('pss', test_utils.make_finalized_inventory(cluster)['rbac'])

    def test_enrich_psp_extra_args_plugins_list(self):
        self._inventory('psp')

        admission_plugins_expected = 'NodeRestriction,PodSecurityPolicy'

        cluster = self._new_cluster()
        apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual(admission_plugins_expected, apiserver_extra_args.get('enable-admission-plugins'))

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual(admission_plugins_expected, apiserver_extra_args.get('enable-admission-plugins'))

    def test_conditional_enrich_pss_extra_args_feature_gates(self):
        for k8s_version, feature_gates_enriched in (('v1.27.8', True), ('v1.28.4', False)):
            with self.subTest(f"Kubernetes: {k8s_version}"):
                self.setUp()
                self._inventory('pss')
                self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version

                feature_gates_expected = 'PodSecurity=true' if feature_gates_enriched else None

                cluster = self._new_cluster()
                apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual(feature_gates_expected, apiserver_extra_args.get('feature-gates'))
                self.assertEqual('/etc/kubernetes/pki/admission.yaml', apiserver_extra_args['admission-control-config-file'])

                finalized_inventory = test_utils.make_finalized_inventory(cluster)
                apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual(feature_gates_expected, apiserver_extra_args.get('feature-gates'))
                self.assertEqual('/etc/kubernetes/pki/admission.yaml', apiserver_extra_args['admission-control-config-file'])
                self.assertNotIn('psp', finalized_inventory['rbac'])

    def test_enrich_pss_extra_args_feature_gates_custom(self):
        self._inventory('pss')
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': 'v1.27.8',
            'apiServer': {'extraArgs': {'feature-gates': 'ServiceAccountIssuerDiscovery=true'}},
        }

        cluster = self._new_cluster()
        apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual('ServiceAccountIssuerDiscovery=true,PodSecurity=true', apiserver_extra_args.get('feature-gates'))

        finalized_inventory = test_utils.make_finalized_inventory(cluster)
        apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual('ServiceAccountIssuerDiscovery=true,PodSecurity=true', apiserver_extra_args.get('feature-gates'))
        self.assertNotIn('psp', finalized_inventory['rbac'])

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
