#!/usr/bin/env python3
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

from kubemarine import kubernetes
from kubemarine.core import utils
from kubemarine.procedures import upgrade
from kubemarine import demo


class UpgradeVerifyUpgradePlan(unittest.TestCase):

    def test_valid_upgrade_plan(self):
        upgrade.verify_upgrade_plan([
            'v1.17.1',
            'v1.18.2'
        ])

    def test_invalid_upgrade_plan(self):
        with self.assertRaises(Exception):
            upgrade.verify_upgrade_plan([
                'v1.17.1',
                'v1.19.3'
            ])

    def test_upgrade_plan_bad_symbols(self):
        with self.assertRaises(Exception):
            upgrade.verify_upgrade_plan([
                'v1.17 .1',
                'v1.18.2'
            ])

    def test_upgrade_plan_invalid_version(self):
        with self.assertRaises(Exception):
            upgrade.verify_upgrade_plan([
                'v1.17',
                'v1.18.2'
            ])

    def test_upgrade_plan_invalid_version2(self):
        with self.assertRaises(Exception):
            upgrade.verify_upgrade_plan([
                '1.17.1',
                '1.18.2'
            ])

    def test_upgrade_plan_sort(self):
        result = upgrade.verify_upgrade_plan([
            'v2.1.1',
            'v1.13.2',
            'v1.15.0',
            'v1.18.2',
            'v1.16.2',
            'v1.14.4',
            'v2.0.3',
            'v1.17.1',
            'v1.13.1',
        ])

        self.assertEqual([
            'v1.13.1',
            'v1.13.2',
            'v1.14.4',
            'v1.15.0',
            'v1.16.2',
            'v1.17.1',
            'v1.18.2',
            'v2.0.3',
            'v2.1.1',
        ], result)


def generate_upgrade_environment(old, new) -> (dict, dict):
    inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
    inventory['services']['kubeadm'] = {
        'kubernetesVersion': old
    }
    context = demo.create_silent_context(procedure='upgrade')
    context['upgrade_version'] = new
    return inventory, context


class UpgradeDefaultsEnrichment(unittest.TestCase):

    def prepare_cluster(self, old, new):
        inventory, context = generate_upgrade_environment(old, new)
        upgrade = {'upgrade_plan': [new]}
        cluster = demo.new_cluster(inventory, procedure_inventory=upgrade, context=context)
        return cluster

    def test_correct_inventory(self):
        old_kubernetes_version = 'v1.24.0'
        new_kubernetes_version = 'v1.24.2'
        cluster = self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)
        self.assertEqual(new_kubernetes_version, cluster.inventory['services']['kubeadm']['kubernetesVersion'])

    def test_incorrect_inventory_high_range(self):
        old_kubernetes_version = 'v1.22.9'
        new_kubernetes_version = 'v1.24.2'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)

    def test_incorrect_inventory_downgrade(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.22.9'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_DOWNGRADE
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)

    def test_incorrect_inventory_same_version(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.2'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_SAME
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)


class UpgradePackagesEnrichment(unittest.TestCase):
    def prepare_procedure_inventory(self, new) -> dict:
        return {
            'upgrade_plan': [new],
            new: {
                'packages': {
                    'associations': {
                        'docker': {
                            'package_name': 'docker-ce'
                        }
                    },
                    'install': ['curl']
                }
            }
        }

    def test_enrich_packages_propagate_associations(self):
        old = 'v1.24.0'
        new = 'v1.24.2'
        inventory, context = generate_upgrade_environment(old, new)
        upgrade = self.prepare_procedure_inventory(new)
        cluster = demo.new_cluster(inventory, procedure_inventory=upgrade, context=context)
        self.assertEqual(['curl'], cluster.inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        self.assertEqual('docker-ce', cluster.inventory['services']['packages']['associations']['rhel']['docker']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_final_inventory_enrich_global(self):
        old = 'v1.24.0'
        new = 'v1.24.2'
        inventory, context = generate_upgrade_environment(old, new)
        upgrade = self.prepare_procedure_inventory(new)
        cluster = demo.new_cluster(deepcopy(inventory), procedure_inventory=deepcopy(upgrade), context=context)
        final_inventory = utils.get_final_inventory(cluster, inventory)
        expected_final_packages = deepcopy(upgrade[new]['packages'])
        expected_final_packages['install'] = {'include': expected_final_packages['install']}
        self.assertEqual(expected_final_packages, final_inventory['services']['packages'],
                         "Final inventory is recreated incorrectly")


if __name__ == '__main__':
    unittest.main()
