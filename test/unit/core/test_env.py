import json
import logging
import os
import re
import tempfile
import unittest
from typing import Dict, Optional
from unittest import mock

from kubemarine import demo, plugins
from kubemarine.core import flow, utils, log, os as kos, yaml
from kubemarine.procedures import install
from test.unit import utils as test_utils


class TestEnvironmentVariables(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(['--without-act'], procedure='install',
                                                  parser=flow.new_tasks_flow_parser("Help text", install.tasks))
        args = self.context['execution_arguments']
        args['disable_dump'] = False
        args['dump_location'] = self.tmpdir.name
        utils.prepare_dump_directory(args['dump_location'])

        self.resources: Optional[demo.FakeResources] = None

    def tearDown(self):
        kos._environ = None
        kos._masked_names = kos._MaskedNames()
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

    def test_masked_allowed_sections(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET1 }}',
        }
        self.inventory['plugins'] = {'my_plugin': {'installation': {'procedures': [
            {'helm': {
                'chart_path': __file__,
                'values_stdin': {
                    'secret': '{{ env.SECRET2 }}',
                }
            }}
        ]}}}
        self.inventory['runtime_values'] = {'masked': [
            'SECRET1', 'SECRET2'
        ]}

        self._run({'SECRET1': 'secret_value1', 'SECRET2': 'secret_value2'})

        inventory = self.resources.last_cluster.inventory
        values_stdin = inventory['plugins']['my_plugin']['installation']['procedures'][0]['helm']['values_stdin']
        self.assertEqual('******', str(inventory['values']['variable']))
        self.assertEqual('******', str(values_stdin['secret']))

    def test_masked_not_allowed_section(self):
        self.inventory['plugins'] = {'my_plugin': {'installation': {'procedures': [
            {'helm': {
                'chart_path': __file__,
                'values': {
                    'secret': '{{ env.SECRET }}',
                }
            }}
        ]}}}
        self.inventory['runtime_values'] = {'masked': ['SECRET']}

        with test_utils.assert_raises_kme(
                self, "KME0015", name='SECRET',
                path=re.escape("['plugins']['my_plugin']['installation']['procedures'][0]['helm']['values']")):
            self._run({'SECRET': 'secret_value'})

    def test_masked_allowed_symbols(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET }}',
        }
        self.inventory['runtime_values'] = {'masked': ['SECRET']}
        self._run({'SECRET': '-=+/@_.:~'})
        inventory = self.resources.last_cluster.inventory
        self.assertEqual('******', str(inventory['values']['variable']))

    def test_masked_illegal_symbols(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET }}',
        }
        self.inventory['runtime_values'] = {'masked': ['SECRET']}
        for ch in ('\n', '"', ' '):
            with self.subTest(json.JSONEncoder().encode(ch)), \
                    test_utils.assert_raises_kme( self, "KME0013", name='SECRET'):
                self._run({'SECRET': 'aaaaaaa' + ch})

    def test_masked_log_message_and_args(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET }}',
        }
        self.inventory['runtime_values'] = {'masked': ['SECRET']}
        resources = self._new_resources()
        secret = 'AZaz09-=+/@_.:~'
        base64_secret = 'QVphejA5LT0rL0BfLjp+'
        with mock.patch.dict(os.environ, {'SECRET': secret}):
            resources.logger().debug(f"Secret {secret} in text.")
            resources.logger().debug(f"{base64_secret} is a base64-encoded text.")
            resources.logger().debug("%s in another text.", secret)

        log_output = utils.read_external(os.path.join(self.tmpdir.name, 'dump', 'debug.log'))

        self.assertTrue('Secret ****** in text.' in log_output, "Secret was not masked")
        self.assertTrue('****** is a base64-encoded text.' in log_output, "Secret was not masked")
        self.assertTrue('****** in another text.' in log_output, "Secret was not masked")
        self.assertFalse(secret in log_output, "Secret was not masked")
        self.assertFalse(base64_secret in log_output, "Secret was not masked")

    def test_masked_log_exception(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET }}',
        }
        self.inventory['runtime_values'] = {'masked': ['SECRET']}
        resources = self._new_resources()
        with mock.patch.dict(os.environ, {'SECRET': 'secret_value'}):
            try:
                raise Exception("Secret in exception message: secret_value")
            except Exception as reason:
                resources.logger().error("Expected exception", exc_info=reason)

        log_output = utils.read_external(os.path.join(self.tmpdir.name, 'dump', 'debug.log'))

        self.assertTrue('Secret in exception message: ******' in log_output, "Secret was not masked")
        self.assertFalse('secret_value' in log_output, "Secret was not masked")

    def test_plugin_template_apply_and_mask(self):
        template_file = os.path.join(self.tmpdir.name, 'template.yaml.j2')
        with utils.open_external(template_file, 'w') as t:
            t.write('Some {{ env.SECRET }}\n')

        self.inventory['plugins'] = {'my_plugin': {
            'install': True,
            'installation': {'procedures': [{'template': template_file}]}
        }}
        self.inventory['runtime_values'] = {'masked': ['SECRET']}
        resources = self._new_resources()
        with mock.patch.object(plugins, plugins.apply_source.__name__) as apply_source, \
                mock.patch.dict(os.environ, {'SECRET': 'secret_value'}):
            cluster = resources.cluster()
            plugins.install(cluster, {'my_plugin': cluster.inventory['plugins']['my_plugin']})

        source = apply_source.call_args[0][1]['source'].getvalue()
        self.assertIn('Some secret_value', source, "Secret should be uploaded on nodes")

        compiled_template = utils.read_external(os.path.join(self.tmpdir.name, 'dump', 'template.yaml'))
        self.assertIn('Some ******', compiled_template, "Secret should be masked in dump files.")

    def test_masked_finalized_inventory(self):
        self.inventory['values'] = {
            'variable': '{{ env.SECRET }}',
        }
        self.inventory['runtime_values'] = {'masked': ['SECRET']}

        self._run({'SECRET': 'secret_value'})

        cluster = self.resources.last_cluster
        test_utils.stub_associations_packages(cluster, {})
        with kos.expand_template('env'):
            data = yaml.dump(cluster.make_finalized_inventory())

        finalized_inventory = yaml.safe_load(data)
        self.assertEqual("{{ env[\"SECRET\"] }}", finalized_inventory['values']['variable'],
                         "Masked variables should be converted to template in finalized inventory")

        with mock.patch.dict(os.environ, {'SECRET': 'secret_value'}):
            cluster = demo.new_cluster(finalized_inventory)

        self.assertEqual("******", str(cluster.inventory['values']['variable']), "Secret was not masked")


if __name__ == '__main__':
    unittest.main()
