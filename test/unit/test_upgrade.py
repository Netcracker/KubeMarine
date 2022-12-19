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
from kubemarine.core import errors
from kubemarine.procedures import upgrade
from kubemarine import demo
from test.unit import utils


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

    def prepare_inventory(self, old, new):
        self.inventory, self.context = generate_upgrade_environment(old, new)
        self.upgrade: dict = {'upgrade_plan': [new]}

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.upgrade, context=self.context)

    def test_correct_inventory(self):
        old_kubernetes_version = 'v1.24.0'
        new_kubernetes_version = 'v1.24.2'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        cluster = self._new_cluster()
        self.assertEqual(new_kubernetes_version, cluster.inventory['services']['kubeadm']['kubernetesVersion'])

    def test_incorrect_inventory_high_range(self):
        old_kubernetes_version = 'v1.22.9'
        new_kubernetes_version = 'v1.24.2'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self._new_cluster()

    def test_incorrect_inventory_downgrade(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.22.9'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_DOWNGRADE
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self._new_cluster()

    def test_incorrect_inventory_same_version(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.2'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_SAME
                                               % (old_kubernetes_version, new_kubernetes_version)):
            self._new_cluster()

    def test_incorrect_disable_eviction(self):
        old_kubernetes_version = 'v1.24.0'
        new_kubernetes_version = 'v1.24.2'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        self.upgrade['disable-eviction'] = 'true'
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'string'\. Expected: 'boolean'\."):
            self._new_cluster()


class UpgradePackagesEnrichment(unittest.TestCase):
    def setUp(self):
        self.old = 'v1.24.0'
        self.new = 'v1.24.2'
        self.inventory, self.context = generate_upgrade_environment(self.old, self.new)
        self.inventory['services']['packages'] = {}
        self.upgrade: dict = {
            'upgrade_plan': [self.new],
            self.new: {
                'packages': {
                    'associations': {
                        'docker': {}
                    }
                }
            }
        }

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.upgrade),
                                context=self.context)

    def test_enrich_packages_propagate_associations(self):
        self.upgrade[self.new]['packages']['associations']['docker']['package_name'] = 'docker-ce'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self._new_cluster()
        self.assertEqual(['curl'], cluster.inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        self.assertEqual('docker-ce', cluster.inventory['services']['packages']['associations']['rhel']['docker']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_final_inventory_enrich_global(self):
        self.upgrade[self.new]['packages']['associations']['docker']['package_name'] = 'docker-ce'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self._new_cluster()
        final_inventory = utils.get_final_inventory(cluster, self.inventory)
        expected_final_packages = deepcopy(self.upgrade[self.new]['packages'])
        expected_final_packages['install'] = {'include': expected_final_packages['install']}
        self.assertEqual(expected_final_packages, final_inventory['services']['packages'],
                         "Final inventory is recreated incorrectly")

    def test_final_inventory_merge_packages(self):
        self.inventory['services']['packages'].setdefault('install', {})['include'] = ['curl']
        self.upgrade[self.new]['packages']['install'] = ['unzip', {'<<': 'merge'}]

        self.inventory['services']['packages'].setdefault('upgrade', {})['exclude'] = ['conntrack']
        self.upgrade[self.new]['packages'].setdefault('upgrade', {})['exclude'] = [{'<<': 'merge'}, 'socat']
        cluster = self._new_cluster()

        self.assertEqual(['unzip', 'curl'], cluster.inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], cluster.inventory['services']['packages']['upgrade']['exclude'])
        self.assertEqual(['*'], cluster.inventory['services']['packages']['upgrade']['include'])

        utils.stub_associations_packages(cluster, {})
        utils.stub_detect_packages(cluster, {"unzip": {}, "curl": {}})

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(['unzip', 'curl'], finalized_inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], finalized_inventory['services']['packages']['upgrade']['exclude'])
        self.assertEqual(['*'], finalized_inventory['services']['packages']['upgrade']['include'])

        final_inventory = utils.get_final_inventory(cluster, self.inventory)
        self.assertEqual(['unzip', 'curl'], final_inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], final_inventory['services']['packages']['upgrade']['exclude'])
        self.assertIsNone(final_inventory['services']['packages']['upgrade'].get('include'))


if __name__ == '__main__':
    unittest.main()
