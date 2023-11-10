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
from kubemarine.core import errors, flow
from kubemarine.procedures import migrate_cri
from test.unit import utils


def generate_migrate_cri_environment() -> (dict, dict):
    inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
    inventory['services']['cri'] = {
        'containerRuntime': 'docker'
    }
    context = demo.create_silent_context(['fake.yaml', '--without-act'], procedure='migrate_cri')
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


class MigrateCriThirdpartiesEnrichment(unittest.TestCase):
    def setUp(self):
        self.inventory, self.context = generate_migrate_cri_environment()
        self.migrate_cri = demo.generate_procedure_inventory('migrate_cri')
        self.migrate_cri['thirdparties'] = {}

    def _run(self) -> demo.FakeResources:
        resources = demo.FakeResources(self.context, self.inventory,
                                       procedure_inventory=self.migrate_cri,
                                       nodes_context=demo.generate_nodes_context(self.inventory))
        flow.run_actions(resources, [migrate_cri.MigrateCRIAction()])
        return resources

    def test_enrich_source_string(self):
        self.migrate_cri['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-new'

        resources = self._run()
        cluster = resources.last_cluster

        thirdparties_section = cluster.inventory['services']['thirdparties']
        self.assertEqual('crictl-new', thirdparties_section['/usr/bin/crictl.tar.gz']['source'])
        self.assertEqual('/usr/bin/', thirdparties_section['/usr/bin/crictl.tar.gz'].get('unpack'))

        utils.stub_associations_packages(cluster, {})
        finalized_inventory = utils.make_finalized_inventory(cluster)

        thirdparties_section = finalized_inventory['services']['thirdparties']
        self.assertEqual('crictl-new', thirdparties_section['/usr/bin/crictl.tar.gz']['source'])
        self.assertEqual('/usr/bin/', thirdparties_section['/usr/bin/crictl.tar.gz'].get('unpack'))

        thirdparties_section = resources.stored_inventory['services']['thirdparties']
        self.assertEqual('crictl-new', thirdparties_section['/usr/bin/crictl.tar.gz']['source'])
        self.assertIsNone(thirdparties_section['/usr/bin/crictl.tar.gz'].get('unpack'))


class MigrateCriRegistryEnrichment(unittest.TestCase):
    def setUp(self):
        self.inventory, self.context = generate_migrate_cri_environment()
        self.migrate_cri = demo.generate_procedure_inventory('migrate_cri')

    def _run(self) -> demo.FakeResources:
        resources = demo.FakeResources(self.context, self.inventory,
                                       procedure_inventory=self.migrate_cri,
                                       nodes_context=demo.generate_nodes_context(self.inventory))
        flow.run_actions(resources, [migrate_cri.MigrateCRIAction()])
        return resources

    def test_apply_custom_unified_registry_in_new_format(self):
        self.inventory['registry'] = {
            'address': 'example.registry',
            'docker_port': 8080,
            'ssl': True
        }
        resources = self._run()
        cluster = resources.last_cluster

        containerd_config = cluster.inventory['services']['cri']['containerdConfig']
        path = 'plugins."io.containerd.grpc.v1.cri"'
        self.assertEqual(f'/etc/containerd/certs.d', containerd_config[f'{path}.registry'].get('config_path'))

        containerd_reg_config = cluster.inventory['services']['cri']['containerdRegistriesConfig']
        registry_settings = containerd_reg_config.get('example.registry:8080')
        self.assertIsNotNone(registry_settings)

        self.assertIn('host."https://example.registry:8080"', registry_settings)
        self.assertEqual(['pull', 'resolve'], registry_settings['host."https://example.registry:8080"'].get('capabilities'))

    def test_merging_endpoint_parameters_in_new_format_with_defaults(self):
        self.inventory['registry'] = {
            'address': 'example.registry-1',
            'docker_port': 8080,
            'ssl': True
        }

        self.migrate_cri['cri']['containerdRegistriesConfig'] = {
            'example.registry-1:8080': {
                'host."https://example.registry-1:8080"': {
                    'skip_verify': True
                },
                'host."https://example.registry-2:8080"': {
                    'capabilities': ['pull', 'push']
                },
            },
            'example.another-registry:8080': {
                'host."https://example.another-registry:8080"': {
                    'capabilities': ['pull']
                }
            }
        }
        resources = self._run()
        cluster = resources.last_cluster

        containerd_config = cluster.inventory['services']['cri']['containerdConfig']
        path = 'plugins."io.containerd.grpc.v1.cri"'
        self.assertEqual(f'/etc/containerd/certs.d', containerd_config[f'{path}.registry'].get('config_path'))

        containerd_reg_config = cluster.inventory['services']['cri']['containerdRegistriesConfig']
        registry_settings_1 = containerd_reg_config.get('example.registry-1:8080')
        self.assertIsNotNone(registry_settings_1)

        self.assertIn('host."https://example.registry-1:8080"', registry_settings_1)
        self.assertEqual(['pull', 'resolve'], registry_settings_1['host."https://example.registry-1:8080"'].get('capabilities'))
        self.assertEqual(True, registry_settings_1['host."https://example.registry-1:8080"'].get('skip_verify'))

        self.assertIn('host."https://example.registry-2:8080"', registry_settings_1)
        self.assertEqual(['pull', 'push'], registry_settings_1['host."https://example.registry-2:8080"'] .get('capabilities'))

        registry_settings_2 = containerd_reg_config.get('example.another-registry:8080')
        self.assertIsNotNone(registry_settings_2)

        self.assertIn('host."https://example.another-registry:8080"', registry_settings_2)
        self.assertEqual(['pull'], registry_settings_2['host."https://example.another-registry:8080"'].get('capabilities'))


if __name__ == '__main__':
    unittest.main()
