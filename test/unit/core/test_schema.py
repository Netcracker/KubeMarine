import unittest
from pathlib import Path
from unittest import mock

import yaml

from kubemarine import demo, coredns, __main__
from kubemarine.core import errors, utils
from kubemarine.procedures import install
from test.unit import utils as test_utils


class FinalizedInventoryValidation(unittest.TestCase):
    def _check_finalized_validation(self, inventory: dict):
        try:
            return demo.new_cluster(inventory)
        except errors.FailException as e:
            self.fail(f"Enrichment of finalized inventory failed: {e.message}")

    def test_simple_inventory_enriches_valid(self):
        inventory = demo.generate_inventory(**demo.FULLHA_KEEPALIVED)
        cluster = demo.new_cluster(inventory)

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        # check that enrichment of finalized inventory is successful and the inventory is valid against the schema
        cluster = self._check_finalized_validation(finalized_inventory)

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        # check that enrichment is idempotent and double-finalized inventory still valid against the schema
        self._check_finalized_validation(finalized_inventory)

    def test_coredns_generation_enriches_valid(self):
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        coredns.generate_configmap(cluster.inventory)

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        # check that generation of coredns does not break finalized inventory
        self._check_finalized_validation(finalized_inventory)

    @mock.patch('kubemarine.plugins.install_plugin')
    def test_plugins_installation_enriches_valid(self, install_plugin):
        inventory = demo.generate_inventory(**demo.MINIHA)
        cluster = demo.new_cluster(inventory)
        install.deploy_plugins(cluster)

        test_utils.stub_associations_packages(cluster, {})
        finalized_inventory = test_utils.make_finalized_inventory(cluster)

        # check that plugins installation does not break finalized inventory
        self._check_finalized_validation(finalized_inventory)


class TestValidExamples(unittest.TestCase):
    def test_cluster_examples_valid(self):
        inventories_dir = utils.get_resource_absolute_path("../examples/cluster.yaml", script_relative=True)
        for inventory_filepath in Path(inventories_dir).glob('*'):
            with open(inventory_filepath, 'r') as stream:
                inventory = yaml.safe_load(stream)

            # check that enrichment is successful and the inventory is valid against the schema
            try:
                demo.new_cluster(inventory)
            except Exception as e:
                self.fail(f"Enrichment of {inventory_filepath.relative_to(inventories_dir)} failed: {e}")

    def test_procedure_examples_valid(self):
        inventories_dir = utils.get_resource_absolute_path("../examples/procedure.yaml", script_relative=True)
        for inventory_filepath in Path(inventories_dir).glob('*'):
            with open(inventory_filepath, 'r') as stream:
                procedure_inventory = yaml.safe_load(stream)

            for procedure in __main__.procedures.keys():
                if procedure in inventory_filepath.name:
                    break
            else:
                self.fail(f"Unknown procedure for inventory {inventory_filepath.relative_to(inventories_dir)}")

            context = demo.create_silent_context(procedure=procedure)
            inventory = demo.generate_inventory(**demo.MINIHA)

            # check that enrichment is successful and the inventory is valid against the schema
            try:
                demo.new_cluster(inventory, context=context, procedure_inventory=procedure_inventory)
            except Exception as e:
                self.fail(f"Enrichment of {inventory_filepath.relative_to(inventories_dir)} failed: {e}")


class TestErrorHeuristics(unittest.TestCase):
    def test_not_of_types(self):
        """
        'vrrp_ips' section is an example where each item can be either string or object.
        Specify some other type to check correctly generated error.
        See kubemarine.core.schema._unnest_type_subschema_errors
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['vrrp_ips'][0] = 123
        with self.assertRaisesRegex(errors.FailException, "123 is not of type 'string', 'object'"):
            demo.new_cluster(inventory)

    def test_key_not_in_propertyNames(self):
        """
        'nodes' section is an example where propertyNames are configured as allOf(enums).
        Specify unexpected property to check correctly generated error.
        See kubemarine.core.schema._unnest_enum_subschema_errors
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['nodes'][0]['unsupported_property'] = 'value'
        with self.assertRaisesRegex(errors.FailException, r"'unsupported_property' is not one of \[.*]"):
            demo.new_cluster(inventory)

    def test_raise_max_relevant_from_subschema(self):
        """
        'vrrp_ips' section is an example where each item can be either string or object.
        If object is supplied, the most relevant error should be raised.
        See kubemarine.core.schema._descend_errors
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['vrrp_ips'][0] = {
            "ip": inventory['vrrp_ips'][0],
            "unsupported_property": 'value',  # unsupported property has greater priority
            "hosts": [
                {
                    "priority": -1  # break the lower bound has lower priority
                }
            ]
        }
        with self.assertRaisesRegex(errors.FailException, r"'unsupported_property' was unexpected"):
            demo.new_cluster(inventory)

    def test_oneOf_object_with_propertyNames(self):
        """
        'services.thirdparties' section is an example where each item can be either string or object,
        and the schema for object is configured with propertyNames assertion.
        Specify unexpected property to check correctly generated error.
        See kubemarine.core.schema._apply_property_names_heuristic
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['thirdparties'] = {
            '/usr/bin/kubeadm': {
                "source": "http://source",
                "unsupported_property": "value"
            }
        }
        with self.assertRaisesRegex(errors.FailException, r"'unsupported_property' is not one of \[.*]"):
            demo.new_cluster(inventory)

    def test_list_merging_strong_heuristic(self):
        """
        'services.audit.cluster_policy.rules' section is an example where each item can be oneOf(object, list merging symbol).
        Omit required property for object to check correctly generated error.
        See kubemarine.core.schema._apply_list_merging_strong_heuristic
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services']['audit'] = {
            'cluster_policy': {
                "rules": [
                    {"<<": "merge"},
                    {"level property present": False}
                ]
            }
        }
        with self.assertRaisesRegex(errors.FailException, r"'level' is a required property"):
            demo.new_cluster(inventory)

    def test_required_and_optional_properties_heuristic(self):
        """
        'registry' section is an example where of oneOf(object, object).
        Specify unexpected properties to check correctly generated error.
        See kubemarine.core.schema._apply_required_and_optional_properties_heuristic
        """
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['registry'] = {
            'address': 'example.com',
            'unsupported_property': False
        }
        with self.assertRaisesRegex(errors.FailException, r"'unsupported_property' was unexpected"):
            demo.new_cluster(inventory)

        inventory['registry'] = {
            'address': 'example.com',
            'endpoints': ['one', 'another']
        }
        with self.assertRaisesRegex(errors.FailException, r"'address' was unexpected"):
            demo.new_cluster(inventory)


if __name__ == '__main__':
    unittest.main()
