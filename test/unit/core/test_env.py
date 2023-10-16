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

import logging
import os
import tempfile
import unittest
from typing import Dict, Optional
from unittest import mock

from kubemarine import demo, plugins
from kubemarine.core import flow, utils, log
from kubemarine.procedures import install


class TestEnvironmentVariables(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(['--without-act'])
        args = self.context['execution_arguments']
        args['disable_dump'] = False
        args['dump_location'] = self.tmpdir.name
        utils.prepare_dump_directory(args['dump_location'])

        self.resources: Optional[demo.FakeResources] = None

    def tearDown(self):
        logger = logging.getLogger("k8s.fake.local")
        for h in logger.handlers:
            if isinstance(h, log.FileHandlerWithHeader):
                h.close()
        self.tmpdir.cleanup()

    def _new_resources(self) -> demo.FakeResources:
        return demo.FakeResources(self.context, self.inventory,
                                  nodes_context=demo.generate_nodes_context(self.inventory))

    def _run(self, mock_environ: Dict[str, str]):
        self.resources = self._new_resources()
        with mock.patch.dict(os.environ, mock_environ):
            flow.run_actions(self.resources, [install.InstallAction()])

    def test_simple_miscellaneous_env_variables(self):
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

        inventory = self.resources.last_cluster.inventory
        self.assertEqual('value1', inventory['values']['variable'])

        config = inventory['services']['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri".registry.configs."host".auth']
        self.assertEqual('me', config['username'])
        self.assertEqual('password123', config['password'])

    def test_substring_jinja_env_variables(self):
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

        inventory = self.resources.last_cluster.inventory
        values = inventory['plugins']['my_plugin']['installation']['procedures'][0]['helm']['values']
        self.assertEqual('test-image:1.2.3', values['image'])
        self.assertEqual('1.2.3', values['version'])

    def test_expression_jinja_env_variables(self):
        self.inventory['values'] = {
            'variable': '{{ env.ENV_NAME1 | default("not defined") }}',
        }
        self._run({})
        inventory = self.resources.last_cluster.inventory
        self.assertEqual('not defined', inventory['values']['variable'])

    def test_recursive_env_variables(self):
        self.inventory['values'] = {
            'variable1': '{{ values.variable3 }}',
            'variable2': '{{ env.ENV_NAME }}',
            'variable3': '{{ values.variable2 }}',
        }
        self._run({'ENV_NAME': 'value-recursive'})
        inventory = self.resources.last_cluster.inventory
        self.assertEqual('value-recursive', inventory['values']['variable1'])
        self.assertEqual('value-recursive', inventory['values']['variable2'])
        self.assertEqual('value-recursive', inventory['values']['variable3'])

    def test_plugin_template_apply_env_variables(self):
        template_file = os.path.join(self.tmpdir.name, 'template.yaml.j2')
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

        compiled_template = utils.read_external(os.path.join(self.tmpdir.name, 'dump', 'template.yaml'))
        self.assertIn('Some env_value', compiled_template, "Env variable should be expanded in dump files.")


if __name__ == '__main__':
    unittest.main()
