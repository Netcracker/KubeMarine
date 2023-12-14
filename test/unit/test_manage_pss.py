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

from kubemarine import demo, admission, plugins
from kubemarine.core import errors, flow
from kubemarine.kubernetes import components
from kubemarine.procedures import manage_pss
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

    def test_inconsistent_config(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.24.11'
        self.inventory['rbac']['admission'] = 'psp'
        with self.assertRaisesRegex(Exception, re.escape(admission.ERROR_INCONSISTENT_INVENTORIES)):
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

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(['a', 'b', 'c'], finalized_inventory['rbac']['pss']['exemptions']['namespaces'])

        final_inventory = cluster.formatted_inventory
        self.assertEqual(['a', 'b', 'c'], final_inventory['rbac']['pss']['exemptions']['namespaces'])

    def test_disable_pss_dont_enrich_feature_gates(self):
        self.inventory['rbac']['pss']['pod-security'] = 'enabled'
        self.manage_pss['pss']['pod-security'] = 'disabled'

        cluster = self._create_cluster()
        apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual('disabled', cluster.inventory['rbac']['pss']['pod-security'])
        self.assertEqual(None, apiserver_extra_args.get('feature-gates'))
        self.assertEqual(None, apiserver_extra_args.get('admission-control-config-file'))

        finalized_inventory = utils.make_finalized_inventory(cluster)
        apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

        self.assertEqual('disabled', finalized_inventory['rbac']['pss']['pod-security'])
        self.assertEqual(None, apiserver_extra_args.get('feature-gates'))
        self.assertEqual(None, apiserver_extra_args.get('admission-control-config-file'))

        final_inventory = cluster.formatted_inventory
        apiserver_extra_args = final_inventory['services'].get('kubeadm', {}).get('apiServer', {}).get('extraArgs', {})

        self.assertEqual('disabled', final_inventory['rbac']['pss']['pod-security'])
        self.assertEqual(None, apiserver_extra_args.get('feature-gates'))
        self.assertEqual(None, apiserver_extra_args.get('admission-control-config-file'))

    def test_enable_pss_conditional_enrich_feature_gates(self):
        for k8s_version, feature_gates_enriched in (('v1.27.8', True), ('v1.28.4', False)):
            with self.subTest(f"Kubernetes: {k8s_version}"):
                self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = k8s_version
                self.inventory['rbac']['pss']['pod-security'] = 'disabled'
                self.manage_pss['pss']['pod-security'] = 'enabled'

                feature_gates_expected = 'PodSecurity=true' if feature_gates_enriched else None

                cluster = self._create_cluster()
                apiserver_extra_args = cluster.inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual('enabled', cluster.inventory['rbac']['pss']['pod-security'])
                self.assertEqual(feature_gates_expected, apiserver_extra_args.get('feature-gates'))
                self.assertEqual('/etc/kubernetes/pki/admission.yaml', apiserver_extra_args.get('admission-control-config-file'))

                finalized_inventory = utils.make_finalized_inventory(cluster)
                apiserver_extra_args = finalized_inventory["services"]["kubeadm"]['apiServer']['extraArgs']

                self.assertEqual('enabled', finalized_inventory['rbac']['pss']['pod-security'])
                self.assertEqual(feature_gates_expected, apiserver_extra_args.get('feature-gates'))
                self.assertEqual('/etc/kubernetes/pki/admission.yaml', apiserver_extra_args.get('admission-control-config-file'))
                self.assertNotIn('psp', finalized_inventory['rbac'])

                final_inventory = cluster.formatted_inventory
                apiserver_extra_args = final_inventory['services'].get('kubeadm', {}).get('apiServer', {}).get('extraArgs', {})

                self.assertEqual('enabled', final_inventory['rbac']['pss']['pod-security'])
                self.assertEqual(None, apiserver_extra_args.get('feature-gates'))
                self.assertEqual(None, apiserver_extra_args.get('admission-control-config-file'))


class RunTasks(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['rbac'] = {
            'admission': 'pss',
            'pss': {
                'pod-security': 'enabled',
                'defaults': {},
            }
        }
        self.manage_pss = demo.generate_procedure_inventory('manage_pss')

    def _run_tasks(self, tasks_filter: str) -> demo.FakeResources:
        context = demo.create_silent_context(
            ['fake.yaml', '--tasks', tasks_filter], procedure='manage_pss')

        nodes_context = demo.generate_nodes_context(self.inventory)
        resources = demo.FakeResources(context, self.inventory,
                                       procedure_inventory=self.manage_pss, nodes_context=nodes_context)
        flow.run_actions(resources, [manage_pss.PSSAction()])
        return resources

    def test_manage_pss_enable_pss(self):
        self.inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.27.8'
        self.inventory['rbac']['pss']['pod-security'] = 'disabled'
        self.manage_pss['pss']['pod-security'] = 'enabled'
        with utils.mock_call(admission.label_namespace_pss), \
                utils.mock_call(admission.copy_pss), \
                utils.mock_call(components.reconfigure_components) as run:
            res = self._run_tasks('manage_pss')

            self.assertTrue(run.called)
            self.assertEqual(['kube-apiserver'], run.call_args[1]['components'],
                             "kube-apiserver was not reconfigured")

            apiserver_extra_args = res.working_inventory['services']['kubeadm']['apiServer']['extraArgs']
            self.assertEqual('PodSecurity=true', apiserver_extra_args.get('feature-gates'),
                             "Unexpected apiserver extra args")

    def test_manage_pss_change_configuration_restart(self):
        self.inventory['rbac']['pss']['pod-security'] = 'enabled'
        self.inventory['rbac']['pss']['defaults']['enforce'] = 'baseline'
        self.manage_pss['pss']['pod-security'] = 'enabled'
        self.manage_pss['pss']['defaults'] = {'enforce': 'restricted'}

        with utils.mock_call(admission.label_namespace_pss), \
                utils.mock_call(admission.copy_pss), \
                utils.mock_call(components._prepare_nodes_to_reconfigure_components), \
                utils.mock_call(components._reconfigure_control_plane_component, return_value=False) as reconfigure_control_plane, \
                utils.mock_call(components._update_configmap, return_value=True), \
                utils.mock_call(components._restart_containers) as restart_containers, \
                utils.mock_call(plugins.expect_pods) as expect_pods:
            self._run_tasks('manage_pss')

            self.assertTrue(reconfigure_control_plane.called,
                            "There should be an attempt to reconfigure kube-apiserver, but nothing is changed")

            self.assertTrue(restart_containers.called)
            self.assertEqual(['kube-apiserver'], restart_containers.call_args[0][2],
                             "kube-apiserver should be restarted")

            self.assertTrue(expect_pods.called)
            self.assertEqual(['kube-apiserver'], expect_pods.call_args[0][1],
                             "kube-apiserver pods should be waited for")


if __name__ == '__main__':
    unittest.main()
