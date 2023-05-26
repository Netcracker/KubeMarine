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
from kubemarine.plugins import manifest
from test.unit import EnvSetup


class EnrichmentValidation(EnvSetup):
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

    def test_verify_python_valid(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'python': {'module': 'm', 'method': 'f'}}
        ]}}}
        demo.new_cluster(inventory)

    def test_verify_shell_empty_command(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'shell': ''}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'' is too short"):
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
        with self.assertRaisesRegex(errors.FailException, r"'' is too short"):
            demo.new_cluster(inventory)

    def test_verify_helm_empty_chart_path(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['plugins'] = {'custom': {'installation': {'procedures': [
            {'helm': {'chart_path': ''}}
        ]}}}
        with self.assertRaisesRegex(errors.FailException, r"'' is too short"):
            demo.new_cluster(inventory)

    def test_verify_manifest_not_found(self):
        for plugin_name in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            with self.subTest(plugin_name):
                inventory = demo.generate_inventory(**demo.ALLINONE)
                plugin_section = inventory.setdefault('plugins', {}).setdefault(plugin_name, {})
                plugin_section['install'] = True
                plugin_section['installation'] = {'procedures': [{'python': {
                    'module': 'plugins/builtin.py',
                    'method': 'apply_yaml',
                    'arguments': {
                        'plugin_name': plugin_name,
                        'original_yaml_path': f"{__file__}/../test_templates/template.conf"
                    }
                }}]}
                with self.assertRaisesRegex(Exception, manifest.ERROR_MANIFEST_NOT_FOUND % ('.*', plugin_name)):
                    demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
