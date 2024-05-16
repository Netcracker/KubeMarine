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

import os
import unittest
from typing import Dict, Optional, List
from unittest import mock
from test.unit import utils as test_utils

from kubemarine import demo, plugins
from kubemarine.core import utils, flow, action
from kubemarine.core.yaml_merger import default_merger
from kubemarine.procedures import install, upgrade, migrate_kubemarine
from kubemarine.procedures.migrate_kubemarine import ThirdpartyUpgradeAction, CriUpgradeAction, BalancerUpgradeAction, \
    PluginUpgradeAction


class TestEnvironmentVariables(test_utils.CommonTest):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.procedure_inventory = None
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.resources: Optional[demo.FakeResources] = None

    def prepare_context(self, args: list = None, procedure: str = 'install'):
        self.context = demo.create_silent_context(args, procedure)  # pylint: disable=attribute-defined-outside-init
        args = self.context['execution_arguments']
        args['disable_dump'] = False
        args['dump_location'] = self.tmpdir
        utils.prepare_dump_directory(self.context)

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.procedure_inventory,
                                        nodes_context=self.nodes_context)

    def _run(self, mock_environ: Dict[str, str], actions: List[action.Action] = None):
        self.resources = self._new_resources()
        with mock.patch.dict(os.environ, mock_environ):
            if actions is None:
                actions = [install.InstallAction()]
            flow.run_actions(self.resources, actions)

    @test_utils.temporary_directory
    def test_simple_miscellaneous_env_variables(self):
        self.prepare_context(['--without-act'])
        self.inventory['values'] = {
            'variable': '{{ env.ENV_NAME }}',
        }
        self.inventory['services']['cri'] = {
            'containerRuntime': 'containerd',
            'containerdConfig': {
                'plugins."io.containerd.grpc.v1.cri".registry.configs."host".auth': {
                    'username': '{{ env.CRI_NAME }}', 'password': '{{ env["CRI_PASS"] }}'
                }
            }
        }

        self._run({'ENV_NAME': 'value1', 'CRI_NAME': 'me', 'CRI_PASS': 'password123'})

        inventory = self.resources.working_inventory
        self.assertEqual('value1', inventory['values']['variable'])

        auth_path = 'plugins."io.containerd.grpc.v1.cri".registry.configs."host".auth'
        config = inventory['services']['cri']['containerdConfig'][auth_path]
        self.assertEqual('me', config['username'])
        self.assertEqual('password123', config['password'])

    @test_utils.temporary_directory
    def test_substring_jinja_env_variables(self):
        self.prepare_context(['--without-act'])
        self.inventory['plugins'] = {'my_plugin': {'installation': {'procedures': [
            {'helm': {
                'chart_path': __file__,
                'values': {
                    'image': 'test-image:{{ env.IMAGE_TAG }}',
                    'version': '{{ env.IMAGE_TAG }}'
                }
            }}
        ]}}}

        self._run({'IMAGE_TAG': '1.2.3'})

        inventory = self.resources.working_inventory
        values = inventory['plugins']['my_plugin']['installation']['procedures'][0]['helm']['values']
        self.assertEqual('test-image:1.2.3', values['image'])
        self.assertEqual('1.2.3', values['version'])

    @test_utils.temporary_directory
    def test_expression_jinja_env_variables(self):
        self.prepare_context(['--without-act'])
        self.inventory['values'] = {
            'variable': '{{ env.ENV_NAME1 | default("not defined") }}',
        }
        self._run({})
        inventory = self.resources.working_inventory
        self.assertEqual('not defined', inventory['values']['variable'])

    @test_utils.temporary_directory
    def test_recursive_env_variables(self):
        self.prepare_context(['--without-act'])
        self.inventory['values'] = {
            'variable1': '{{ values.variable3 }}',
            'variable2': '{{ env.ENV_NAME }}',
            'variable3': '{{ values.variable2 }}',
        }
        self._run({'ENV_NAME': 'value-recursive'})
        inventory = self.resources.working_inventory
        self.assertEqual('value-recursive', inventory['values']['variable1'])
        self.assertEqual('value-recursive', inventory['values']['variable2'])
        self.assertEqual('value-recursive', inventory['values']['variable3'])

    @test_utils.temporary_directory
    def test_plugin_template_apply_env_variables(self):
        self.prepare_context()
        template_file = os.path.join(self.tmpdir, 'template.yaml.j2')
        with utils.open_external(template_file, 'w') as t:
            t.write('Some {{ env.ENV_VAR }}\n')

        self.inventory['plugins'] = {'my_plugin': {
            'install': True,
            'installation': {'procedures': [{'template': template_file}]}
        }}
        resources = self._new_resources()
        with mock.patch.object(plugins, plugins.apply_source.__name__) as apply_source, \
                mock.patch.dict(os.environ, {'ENV_VAR': 'env_value'}):
            cluster = resources.cluster()
            plugins.install(cluster, {'my_plugin': cluster.inventory['plugins']['my_plugin']})

        source = apply_source.call_args[0][1]['source'].getvalue()
        self.assertIn('Some env_value', source, "Env variable should be expanded")

        compiled_template = utils.read_external(os.path.join(self.tmpdir, 'dump', 'template.yaml'))
        self.assertIn('Some env_value', compiled_template, "Env variable should be expanded in dump files.")

    @test_utils.temporary_directory
    def test_kubernetes_version_env_variable(self):
        kubernetes_version = 'v1.28.4'
        self.prepare_context(['--without-act'])
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': "{{ env.KUBERNETES_VERSION }}"
        }

        self._run({'KUBERNETES_VERSION': kubernetes_version})

        inventory = self.resources.working_inventory
        self.assertEqual(kubernetes_version, inventory['services']['kubeadm']['kubernetesVersion'])
        expected_source = (f'https://storage.googleapis.com/kubernetes-release/release/'
                           f'{kubernetes_version}/bin/linux/amd64/kubeadm')
        self.assertEqual(expected_source,
                         inventory['services']['thirdparties']['/usr/bin/kubeadm']['source'])

    @test_utils.temporary_directory
    def test_kubernetes_version_upgrade_env_variable(self):
        before, after = 'v1.27.13', 'v1.28.9'
        self.prepare_context(['fake_path.yaml', '--without-act'], procedure='upgrade')
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': "{{ env.KUBERNETES_VERSION }}"
        }
        self.inventory['services']['packages'] = {
            'associations': {'containerd': {'package_name': 'containerd_old'}}
        }
        self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
        upgrade_plan = ['{{ env.UPGRADE_VERSION }}']
        self.procedure_inventory['upgrade_plan'] = upgrade_plan
        self.procedure_inventory.setdefault('{{ env.UPGRADE_VERSION }}', {})['packages'] = {
            'associations': {'containerd': {'package_name': 'containerd_new'}}
        }

        self._run({'KUBERNETES_VERSION': before, 'UPGRADE_VERSION': after},
                  [upgrade.UpgradeAction(upgrade_plan[0], 0)])

        inventory = self.resources.working_inventory
        self.assertEqual(after, inventory['services']['kubeadm']['kubernetesVersion'])
        self.assertEqual(f'https://storage.googleapis.com/kubernetes-release/release/{after}/bin/linux/amd64/kubeadm',
                         inventory['services']['thirdparties']['/usr/bin/kubeadm']['source'])
        self.assertEqual('containerd_new',
                         inventory['services']['packages']['associations']['rhel']['containerd']['package_name'])

    @test_utils.temporary_directory
    def test_kubernetes_version_env_variable_migrate_kubemarine_upgrade_patches(self):
        # pylint: disable=protected-access

        self.prepare_context(procedure='migrate_kubemarine')
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': "{{ env.KUBERNETES_VERSION }}"
        }
        self.inventory.setdefault('services', {}).setdefault('cri', {})['containerRuntime'] = 'containerd'
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='22.04')

        env_kubernetes_version = 'v1.27.13'
        changed_upgrade_config = {
            'thirdparties': {'crictl': [env_kubernetes_version]},
            'packages': {
                'containerd': {'version_debian': [env_kubernetes_version]},
                'haproxy': {'version_debian': True},
            },
            'plugins': {
                'calico': [env_kubernetes_version],
            },
        }
        with test_utils.backup_software_upgrade_config() as upgrade_config, \
                mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__) as thirdparty_run, \
                mock.patch.object(CriUpgradeAction, CriUpgradeAction._run.__name__) as cri_run, \
                mock.patch.object(BalancerUpgradeAction, BalancerUpgradeAction._run.__name__) as balancer_run, \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__) as plugin_run:

            default_merger.merge(upgrade_config, changed_upgrade_config)
            actions = [p.action for p in migrate_kubemarine.load_patches()
                       if p.identifier in ['upgrade_crictl', 'upgrade_cri', 'upgrade_haproxy', 'upgrade_calico']]

            self._run({'KUBERNETES_VERSION': env_kubernetes_version}, actions)

            for run in (thirdparty_run, cri_run, balancer_run, plugin_run):
                self.assertTrue(run.called, f"Upgrade patch was not run")


if __name__ == '__main__':
    unittest.main()
