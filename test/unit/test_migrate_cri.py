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
from test.unit import utils


def generate_migrate_cri_environment() -> (dict, dict):
    inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
    inventory['services']['cri'] = {
        'containerRuntime': 'docker'
    }
    context = demo.create_silent_context(['fake.yaml'], procedure='migrate_cri')
    return inventory, context


class EnrichmentValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.context = demo.create_silent_context(['fake.yaml'], procedure='migrate_cri')
        self.migrate_cri = demo.generate_procedure_inventory('migrate_cri')
        del self.migrate_cri['cri']

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.migrate_cri, context=self.context)

    def test_missed_cri(self):
        with self.assertRaisesRegex(errors.FailException,  r"'cri' is a required property"):
            self._new_cluster()

    def test_missed_cri_container_runtime(self):
        self.migrate_cri['cri'] = {}
        with self.assertRaisesRegex(errors.FailException,  r"'containerRuntime' is a required property"):
            self._new_cluster()

    def test_migrate_not_containerd(self):
        self.migrate_cri['cri'] = {'containerRuntime': 'docker'}
        with self.assertRaisesRegex(errors.FailException, r"Value should be one of \['containerd']"):
            self._new_cluster()


class MigrateCriPackagesEnrichment(unittest.TestCase):
    def prepare_procedure_inventory(self):
        migrate_cri = demo.generate_procedure_inventory('migrate_cri')
        migrate_cri['packages'] = {
            'associations': {
                'containerd': {
                    'package_name': 'containerd'
                }
            }
        }
        return migrate_cri

    def test_enrich_packages_propagate_associations(self):
        inventory, context = generate_migrate_cri_environment()
        migrate_cri = self.prepare_procedure_inventory()
        cluster = demo.new_cluster(inventory, procedure_inventory=migrate_cri, context=context)
        self.assertEqual('containerd', cluster.inventory['services']['packages']['associations']['rhel']['containerd']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_final_inventory_enrich_global(self):
        inventory, context = generate_migrate_cri_environment()
        migrate_cri = self.prepare_procedure_inventory()
        cluster = demo.new_cluster(deepcopy(inventory), procedure_inventory=deepcopy(migrate_cri), context=context)
        final_inventory = utils.get_final_inventory(cluster, inventory)
        self.assertEqual(migrate_cri['packages'], final_inventory['services']['packages'],
                         "Final inventory is recreated incorrectly")


if __name__ == '__main__':
    unittest.main()
