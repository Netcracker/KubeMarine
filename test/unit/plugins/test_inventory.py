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
from unittest.mock import patch
from copy import deepcopy

from kubemarine import demo
from kubemarine.core import errors
from kubemarine.plugins import manifest, builtin

MOCK_SPEC = unittest.mock.MagicMock(loader=unittest.mock.MagicMock(exec_module=unittest.mock.MagicMock()))

class EnrichmentValidation(unittest.TestCase):
    def test_unsupported_procedure_type(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'unexpected': 'do something'}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'unexpected' was unexpected"):
            demo.new_cluster(inventory)

    def test_verify_expect_required_list(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        for resource_type in ('daemonsets', 'replicasets', 'statefulsets', 'deployments', 'pods'):
            inventory['plugins'] = {'custom': {'installation': {'procedures': [
                {'expect': {resource_type: {'not a list': 'something'}}}
            ]}}}
            with self.assertRaisesRegex(errors.FailException, r"'list' is a required property"):
                demo.new_cluster(deepcopy(inventory))

    def test_apply_expect_unknown_resource(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'expect': {'unknown resource': {'list': ['one', 'another']}}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'unknown resource' was unexpected"):
            demo.new_cluster(inventory)

    def test_verify_python_module_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'method': 'f'}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'module' is a required property"):
            demo.new_cluster(inventory)

    def test_verify_python_method_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'module': 'm'}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'method' is a required property"):
            demo.new_cluster(inventory)

    def test_verify_python_module_not_exist(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'module': 'm', 'method': 'f'}}
        ]}}}
        with self.assertRaisesRegex(Exception, r"Requested resource m is not exists"):
            demo.new_cluster(inventory)

    @patch('kubemarine.core.utils.determine_resource_absolute_file', return_value=("path", True))
    def test_verify_python_import_error(self, _patch):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'module': 'm', 'method': 'f'}}
        ]}}}

        with self.assertRaisesRegex(Exception, r"Could not import module"):
            demo.new_cluster(inventory) 

    @patch('kubemarine.core.utils.determine_resource_absolute_file', return_value=("path", True))
    @patch('importlib.util.spec_from_file_location', return_value=MOCK_SPEC)
    @patch('importlib.util.module_from_spec', return_value=None)
    def test_verify_python_method_not_exist(self, _patch, _patch1, _patch2):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'module': 'plugins/builtin.py', 'method': 'apply_yaml'}}
        ]}}}
        with self.assertRaisesRegex(Exception, r"Module path does not have method apply_yaml"):
            demo.new_cluster(inventory) 

    def test_verify_shell_empty_command(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'shell': ''}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'' should be non-empty"):
            demo.new_cluster(inventory)

    def test_verify_shell_in_var_name_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'shell': {'command': 'test', 'in_vars': [{}]}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'name' is a required property"):
            demo.new_cluster(inventory)

    def test_verify_shell_out_var_name_not_defined(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'shell': {'command': 'test', 'out_vars': [{}]}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'name' is a required property"):
            demo.new_cluster(inventory)

    def test_verify_shell_correct(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'shell': {'command': 'test', 'in_vars': [{'name': 'a'}], 'out_vars': [{'name': 'a'}]}}
        ]}}}
        demo.new_cluster(inventory)

    def test_verify_ansible_empty_playbook(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'ansible': ''}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'' should be non-empty"):
            demo.new_cluster(inventory)

    def test_verify_helm_empty_chart_path(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'helm': {'chart_path': ''}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'' should be non-empty"):
            demo.new_cluster(inventory)

    def test_verify_manifest_not_found(self):
        for test_identity in builtin.MANIFEST_PROCESSOR_PROVIDERS:
            plugin_name = test_identity.plugin_name
            with self.subTest(test_identity.name):
                inventory = demo.generate_inventory(**demo.ALLINONE)
                plugin_section = inventory.setdefault('plugins', {}).setdefault(plugin_name, {})
                plugin_section['install'] = True

                arguments = {
                    'plugin_name': plugin_name,
                    'original_yaml_path': f"{__file__}/../test_templates/template.conf"
                }
                if test_identity.manifest_id is not None:
                    arguments['manifest_id'] = test_identity.manifest_id

                if test_identity == manifest.Identity("calico", "apiserver"):
                    plugin_section.setdefault('apiserver', {})['enabled'] = True

                plugin_section['installation'] = {'procedures': [{'python': {
                    'module': 'plugins/builtin.py',
                    'method': 'apply_yaml',
                    'arguments': arguments
                }}]}
                manifest_ref = (f'manifest.*{test_identity.manifest_id!r}'
                                if test_identity.manifest_id is not None else 'manifest')
                with self.assertRaisesRegex(Exception, manifest.ERROR_MANIFEST_NOT_FOUND.format(
                        manifest=manifest_ref, path='.*', plugin=plugin_name)):
                    demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
