#!/usr/bin/env python3

import unittest

from kubetool import kubernetes
from kubetool.procedures import upgrade
from kubetool import demo


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


class UpgradeDefaultsEnrichment(unittest.TestCase):

    def prepare_cluster(self, old, new):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        inventory['services']['kubeadm'] = {
            'kubernetesVersion': old
        }
        cluster = demo.new_cluster(inventory)
        cluster.context['upgrade_version'] = new
        cluster.context['initial_procedure'] = 'upgrade'
        return cluster

    def test_correct_inventory(self):
        old_kubernetes_version = 'v1.22.2'
        new_kubernetes_version = 'v1.22.10'
        cluster = self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)
        cluster._inventory = kubernetes.enrich_upgrade_inventory(cluster.inventory, cluster)
        self.assertEqual(new_kubernetes_version, cluster.inventory['services']['kubeadm']['kubernetesVersion'])

    def test_incorrect_inventory_high_range(self):
        old_kubernetes_version = 'v1.22.2'
        new_kubernetes_version = 'v1.28.2'
        cluster = self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaises(Exception):
            kubernetes.enrich_upgrade_inventory(cluster.inventory, cluster)

    def test_incorrect_inventory_downgrade(self):
        old_kubernetes_version = 'v1.22.2'
        new_kubernetes_version = 'v1.18.4'
        cluster = self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaises(Exception):
            kubernetes.enrich_upgrade_inventory(cluster.inventory, cluster)

    def test_incorrect_inventory_same_version(self):
        old_kubernetes_version = 'v1.22.2'
        new_kubernetes_version = 'v1.22.4'
        cluster = self.prepare_cluster(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaises(Exception):
            kubernetes.enrich_upgrade_inventory(cluster.inventory, cluster)


if __name__ == '__main__':
    unittest.main()
