import unittest
from copy import deepcopy

from kubemarine import demo
from kubemarine.core import errors


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


if __name__ == '__main__':
    unittest.main()
