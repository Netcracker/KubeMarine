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

import yaml

from kubemarine import demo, plugins, admission
from kubemarine.core import errors, flow
from kubemarine.kubernetes import components
from kubemarine.procedures import manage_psp
from test.unit import utils as test_utils


def stub_resource(kind: str, name: str = 'custom'):
    return {
        'apiVersion': 'policy/v1beta1',
        'kind': kind,
        'metadata': {
            'name': name
        }
    }


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': 'psp',
            'psp': {
                'pod-security': 'enabled'
            }
        }
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.24.11'
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
            self.manage_psp['psp'][custom_policy_op] = {'psp-list': [stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['PodSecurityPolicy']"):
                self._create_cluster()

    def test_custom_roles_list_unexpected_kind(self):
        for custom_policy_op in ('add-policies', 'delete-policies'):
            self.manage_psp['psp'][custom_policy_op] = {'roles-list': [stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['Role', 'ClusterRole']"):
                self._create_cluster()

    def test_custom_bindings_list_unexpected_kind(self):
        for custom_policy_op in ('add-policies', 'delete-policies'):
            self.manage_psp['psp'][custom_policy_op] = {'bindings-list': [stub_resource('Unexpected')]}
            with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['RoleBinding', 'ClusterRoleBinding']"):
                self._create_cluster()

    def test_forbidden_change_oob_policies_disabled(self):
        self.inventory['rbac']['psp']['pod-security'] = 'disabled'
        del self.manage_psp['psp']['pod-security']
        self.manage_psp['psp']['oob-policies'] = {'default': 'disabled'}
        with self.assertRaisesRegex(Exception, re.escape(admission.ERROR_CHANGE_OOB_PSP_DISABLED)):
            self._create_cluster()

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

    def test_enrich_and_finalize_inventory(self):
        self.inventory['rbac']['psp']['oob-policies'] = {
            'anyuid': 'disabled'
        }
        self.inventory['rbac']['psp']['custom-policies'] = {
            'psp-list': [
                stub_resource('PodSecurityPolicy', 'psp1-old'),
                stub_resource('PodSecurityPolicy', 'psp2-old'),
                stub_resource('PodSecurityPolicy', 'psp3-old'),
            ],
            'roles-list': [stub_resource('Role', 'roles1-old')],
        }

        self.manage_psp['psp']['oob-policies'] = {
            'anyuid': 'enabled',
            'default': 'disabled'
        }
        self.manage_psp['psp']['add-policies'] = {
            'psp-list': [
                stub_resource('PodSecurityPolicy', 'psp3-old'),
                stub_resource('PodSecurityPolicy', 'psp4-new'),
            ],
            'bindings-list': [stub_resource('RoleBinding', 'rb1-new')],
        }
        self.manage_psp['psp']['delete-policies'] = {
            'psp-list': [
                stub_resource('PodSecurityPolicy', 'psp2-old'),
            ]
        }

        cluster = self._create_cluster()

        psp = cluster.inventory['rbac']['psp']
        self._test_enrich_and_finalize_inventory_check(psp, True)

        psp = test_utils.make_finalized_inventory(cluster)['rbac']['psp']
        self._test_enrich_and_finalize_inventory_check(psp, True)

        psp = cluster.formatted_inventory['rbac']['psp']
        self._test_enrich_and_finalize_inventory_check(psp, False)

        psp_list_add = {item["metadata"]["name"] for item in cluster.procedure_inventory['psp']['add-policies']['psp-list']}
        self.assertEqual({'psp3-old', 'psp4-new'}, psp_list_add)

        bindings_list_add = {item["metadata"]["name"] for item in cluster.procedure_inventory['psp']['add-policies']['bindings-list']}
        self.assertEqual({'rb1-new'}, bindings_list_add)

        psp_list_delete = {item["metadata"]["name"] for item in cluster.procedure_inventory['psp']['delete-policies']['psp-list']}
        self.assertEqual({'psp2-old'}, psp_list_delete)

    def _test_enrich_and_finalize_inventory_check(self, psp: dict, enriched: bool):
        self.assertEqual('enabled', psp['oob-policies']['anyuid'])
        self.assertEqual('disabled', psp['oob-policies']['default'])
        self.assertEqual(enriched, psp['oob-policies'].get('host-network') == 'enabled')

        psp_list = {item["metadata"]["name"] for item in psp['custom-policies']['psp-list']}
        self.assertEqual({'psp1-old', 'psp3-old', 'psp4-new'}, psp_list)

        roles_list = {item["metadata"]["name"] for item in psp['custom-policies']['roles-list']}
        self.assertEqual({'roles1-old'}, roles_list)

        bindings_list = {item["metadata"]["name"] for item in psp['custom-policies']['bindings-list']}
        self.assertEqual({'rb1-new'}, bindings_list)

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

        self.fake_shell = demo.FakeShell()
        self.fake_fs = demo.FakeFS()

    def _run_tasks(self, tasks_filter: str) -> demo.FakeResources:
        context = demo.create_silent_context(
            ['fake.yaml', '--tasks', tasks_filter], procedure='manage_psp')

        nodes_context = demo.generate_nodes_context(self.inventory)
        resources = demo.FakeResources(context, self.inventory,
                                       procedure_inventory=self.manage_psp, nodes_context=nodes_context,
                                       fake_shell=self.fake_shell, fake_fs=self.fake_fs)
        flow.run_actions(resources, [manage_psp.PSPAction()])
        return resources

    def test_reconfigure_custom_policies_oob_not_reconfigured(self):
        self.manage_psp['psp']['add-policies'] = {
            'psp-list': [
                stub_resource('PodSecurityPolicy', 'test-psp'),
            ],
        }
        # Nothing is changed on nodes
        self._run_tasks('reconfigure_psp')

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

    def test_reconfigure_oob_policies_one_disable(self):
        self.manage_psp['psp']['oob-policies'] = {
            'anyuid': 'disabled',
        }

        with test_utils.mock_remote_tmp_paths(['delete_policies', 'apply_policies']):
            first_control_plane = self.inventory['nodes'][0]['address']
            results = demo.create_hosts_result([first_control_plane], stdout='applied / deleted')
            manage_policy = "kubectl %s -f %s"
            delete_file = "rm -f %s"

            commands = [
                manage_policy % ('delete', '/tmp/privileged.yaml'),
                manage_policy % ('apply', '/tmp/privileged.yaml'),
                manage_policy % ('delete', '/tmp/delete_policies'),
                manage_policy % ('apply', '/tmp/apply_policies'),
                delete_file % ('/tmp/delete_policies',),
                delete_file % ('/tmp/apply_policies',),
            ]

            for command in commands:
                self.fake_shell.add(results, 'sudo', [command])

            self._run_tasks('reconfigure_psp')

            for command in commands:
                self.assertTrue(self.fake_shell.is_called(first_control_plane, 'sudo', [command]))

            deleted_policies = self.fake_fs.read(first_control_plane, '/tmp/delete_policies')
            deleted_resources = [(resource['kind'], resource['metadata']['name'])
                                 for resource in yaml.safe_load_all(deleted_policies)
                                 if resource is not None]

            self.assertEqual(
                [
                    ('PodSecurityPolicy', 'oob-default-psp'), ('PodSecurityPolicy', 'oob-host-network-psp'), ('PodSecurityPolicy', 'oob-anyuid-psp'),
                    ('ClusterRole', 'oob-default-psp-cr'), ('ClusterRole', 'oob-host-network-psp-cr'), ('ClusterRole', 'oob-anyuid-psp-cr'),
                    ('ClusterRoleBinding', 'oob-default-psp-crb'),
                ],
                deleted_resources
            )

            applied_policies = self.fake_fs.read(first_control_plane, '/tmp/apply_policies')
            applied_resources = [(resource['kind'], resource['metadata']['name'])
                                 for resource in yaml.safe_load_all(applied_policies)
                                 if resource is not None]

            self.assertEqual(
                [
                    ('PodSecurityPolicy', 'oob-default-psp'), ('PodSecurityPolicy', 'oob-host-network-psp'),
                    ('ClusterRole', 'oob-default-psp-cr'), ('ClusterRole', 'oob-host-network-psp-cr'),
                    ('ClusterRoleBinding', 'oob-default-psp-crb'),
                ],
                applied_resources
            )


if __name__ == '__main__':
    unittest.main()
