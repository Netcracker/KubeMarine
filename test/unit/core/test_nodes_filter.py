#!/usr/bin/env python3
# Copyright 2021-2022 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from kubemarine import demo
from kubemarine.core import utils, group as core_group
from kubemarine.kubernetes import get_group_for_upgrade


class ParseNodesFilterExpr(unittest.TestCase):
    def test_empty(self):
        self.assertEqual({}, utils.parse_nodes_filter_expr(''))
        self.assertEqual({}, utils.parse_nodes_filter_expr('   '))

    def test_labels_only_single(self):
        selectors = utils.parse_nodes_filter_expr('labels=region=infra')
        self.assertEqual({'labels': {'region': 'infra'}}, selectors)

    def test_labels_multiple(self):
        selectors = utils.parse_nodes_filter_expr('labels=region=infra;zone=dc1')
        self.assertEqual({'labels': {'region': 'infra', 'zone': 'dc1'}}, selectors)

    def test_roles_only(self):
        selectors = utils.parse_nodes_filter_expr('roles=worker')
        self.assertEqual({'roles': ['worker']}, selectors)

    def test_roles_multiple(self):
        selectors = utils.parse_nodes_filter_expr('roles=worker;control-plane')
        self.assertEqual({'roles': ['worker', 'control-plane']}, selectors)

    def test_labels_and_roles(self):
        selectors = utils.parse_nodes_filter_expr('labels=region=infra;zone=dc1,roles=worker')
        self.assertEqual({'labels': {'region': 'infra', 'zone': 'dc1'}, 'roles': ['worker']}, selectors)


class CliNodesFilterApplication(unittest.TestCase):
    def setUp(self) -> None:
        # All-in-one inventory, add labels per node to distinguish them.
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        for i, node in enumerate(self.inventory['nodes']):
            if 'worker' in node['roles']:
                node.setdefault('labels', {})
                node['labels']['region'] = 'infra' if i % 2 == 0 else 'edge'

    def test_make_group_from_roles_filtered_by_labels(self):
        context = demo.create_silent_context(['--tasks', 'deploy', '--nodes', 'labels=region=infra'])
        cluster = demo.new_cluster(self.inventory, context=context)

        group = cluster.make_group_from_roles(['worker'])
        worker_names = set(group.get_nodes_names())

        expected = {node['name'] for node in self.inventory['nodes']
                    if 'worker' in node['roles'] and node.get('labels', {}).get('region') == 'infra'}
        self.assertEqual(expected, worker_names)


class UpgradeNodesSelector(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = demo.generate_inventory(**demo.FULLHA)
        # Mark only a subset of nodes with a specific label.
        for node in self.inventory['nodes']:
            if 'worker' in node['roles']:
                node.setdefault('labels', {})
                node['labels']['region'] = 'infra'

    def test_upgrade_nodes_by_labels_selector(self):
        procedure_inventory = {
            # Use a version that is present in the compatibility map and higher than the default one
            # from the demo inventory, so that upgrade prechecks pass.
            'upgrade_plan': ['v1.34.1'],
            'upgrade_nodes': {
                'labels': {
                    'region': 'infra',
                },
            },
        }
        context = demo.create_silent_context(['procedure.yaml', '--tasks', 'kubernetes'], procedure='upgrade')
        # Emulate the first upgrade step as the real upgrade procedure does.
        context['upgrade_step'] = 0
        # Use demo.new_cluster to get a cluster with fully mocked nodes context.
        cluster = demo.new_cluster(self.inventory, procedure_inventory=procedure_inventory, context=context)

        # Avoid hitting the real sudo call for removing cached versions file on the control plane by
        # patching NodeGroup.sudo just for this test.
        original_sudo = core_group.NodeGroup.sudo

        def patched_sudo(self, command: str, *args, **kwargs):  # type: ignore[override]
            if command == 'rm -f /etc/kubernetes/nodes-k8s-versions.txt':
                return None
            return original_sudo(self, command, *args, **kwargs)

        core_group.NodeGroup.sudo = patched_sudo  # type: ignore[assignment]
        try:
            group = get_group_for_upgrade(cluster)
        finally:
            core_group.NodeGroup.sudo = original_sudo  # type: ignore[assignment]
        selected_names = set(group.get_nodes_names())
        expected = {node['name'] for node in self.inventory['nodes']
                    if 'worker' in node['roles'] and node.get('labels', {}).get('region') == 'infra'}
        self.assertEqual(expected, selected_names)


if __name__ == '__main__':
    unittest.main()


