import unittest
from copy import deepcopy

from kubemarine import demo
from kubemarine.core import utils


def generate_migrate_cri_environment() -> (dict, dict):
    inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
    inventory['services']['cri'] = {
        'containerRuntime': 'docker'
    }
    context = demo.create_silent_context(procedure='migrate_cri')
    return inventory, context


class MigrateCriPackagesEnrichment(unittest.TestCase):
    def prepare_procedure_inventory(self):
        return {
            'cri': {
                'containerRuntime': 'containerd'
            },
            'packages': {
                'associations': {
                    'containerd': {
                        'package_name': 'containerd'
                    }
                }
            }
        }

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
