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

from kubemarine import demo, plugins, admission
from kubemarine.core import errors, flow
from kubemarine.kubernetes import components
from kubemarine.procedures import manage_psp
from test.unit import utils as test_utils


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

    def test_inconsistent_config(self):
        self.inventory['rbac']['admission'] = 'pss'
        with self.assertRaisesRegex(Exception, re.escape(admission.ERROR_INCONSISTENT_INVENTORIES)):
            self._create_cluster()


class EnrichmentAndFinalization(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.24.11'
        self.inventory['rbac'] = {
            'admission': 'psp',
            'psp': {
                'pod-security': 'enabled',
            }
        }
        self.context = demo.create_silent_context(['fake.yaml'], procedure='manage_psp')
        self.manage_psp = demo.generate_procedure_inventory('manage_psp')

    def _create_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.manage_psp,
                                context=self.context)

    def test_change_psp_state(self):
        for target_state_enabled in (False, True):
            target_state = 'enabled' if target_state_enabled else 'disabled'
            previous_state = 'disabled' if target_state_enabled else 'enabled'
            with self.subTest(f"Target state: {target_state}"):
                self.inventory['rbac']['psp']['pod-security'] = previous_state
                self.manage_psp['psp']['pod-security'] = target_state

                admission_plugins_expected = 'NodeRestriction'
                if target_state_enabled:
                    admission_plugins_expected += ',PodSecurityPolicy'

                cluster = self._create_cluster()
                apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual(target_state, cluster.inventory['rbac']['psp']['pod-security'])
                self.assertEqual(admission_plugins_expected, apiserver_extra_args.get('enable-admission-plugins'))

                finalized_inventory = test_utils.make_finalized_inventory(cluster)
                apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual(target_state, finalized_inventory['rbac']['psp']['pod-security'])
                self.assertEqual(admission_plugins_expected, apiserver_extra_args.get('enable-admission-plugins'))

                final_inventory = cluster.formatted_inventory
                apiserver_extra_args = final_inventory['services'].get('kubeadm', {}).get('apiServer', {}).get('extraArgs', {})

                self.assertEqual(target_state, final_inventory['rbac']['psp']['pod-security'])
                self.assertEqual(None, apiserver_extra_args.get('enable-admission-plugins'))


class RunTasks(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.24.11'
        self.inventory['rbac'] = {
            'admission': 'psp',
            'psp': {
                'pod-security': 'enabled',
            }
        }
        self.manage_psp = demo.generate_procedure_inventory('manage_psp')

    def _run_tasks(self, tasks_filter: str) -> demo.FakeResources:
        context = demo.create_silent_context(
            ['fake.yaml', '--tasks', tasks_filter], procedure='manage_psp')

        nodes_context = demo.generate_nodes_context(self.inventory)
        resources = demo.FakeResources(context, self.inventory,
                                       procedure_inventory=self.manage_psp, nodes_context=nodes_context)
        flow.run_actions(resources, [manage_psp.PSPAction()])
        return resources

    def test_reconfigure_plugin_disable_psp(self):
        self.inventory['rbac']['psp']['pod-security'] = 'enabled'
        self.manage_psp['psp']['pod-security'] = 'disabled'
        with test_utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                test_utils.mock_call(admission.delete_privileged_policy), \
                test_utils.mock_call(admission.manage_policies), \
                test_utils.mock_call(components._reconfigure_control_plane_component, return_value=True) as reconfigure_control_plane, \
                test_utils.mock_call(components._update_configmap, return_value=True), \
                test_utils.mock_call(components._restart_containers) as restart_containers, \
                test_utils.mock_call(plugins.expect_pods) as expect_pods:
            res = self._run_tasks('reconfigure_psp')

            self.assertTrue(reconfigure_control_plane.called,
                            "There should be a successful attempt to reconfigure kube-apiserver")

            self.assertTrue(restart_containers.called)
            self.assertEqual(['kube-apiserver'], restart_containers.call_args[0][2],
                             "kube-apiserver should be restarted")

            self.assertTrue(expect_pods.called)
            self.assertEqual(['kube-apiserver'], expect_pods.call_args[0][1],
                             "kube-apiserver pods should be waited for")

            admission_plugins_expected = 'NodeRestriction'
            apiserver_extra_args = res.working_inventory['services']['kubeadm']['apiServer']['extraArgs']
            self.assertEqual(admission_plugins_expected, apiserver_extra_args.get('enable-admission-plugins'),
                             "Unexpected apiserver extra args")


if __name__ == '__main__':
    unittest.main()
