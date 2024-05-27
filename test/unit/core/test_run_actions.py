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
import collections
import io
import os
import tarfile
import unittest
from contextlib import contextmanager
from textwrap import dedent
from typing import Set, List, Optional
from unittest import mock
from test.unit import utils as test_utils

import yaml

from kubemarine import demo, kubernetes, testsuite, procedures
from kubemarine.core import flow, action, utils, schema, resources as res, summary, defaults
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage
from kubemarine.core.yaml_merger import default_merger
from kubemarine.procedures import upgrade, install, check_iaas, check_paas, migrate_kubemarine
from kubemarine.procedures.migrate_kubemarine import CriUpgradeAction, PluginUpgradeAction


class ActionsFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.context = demo.create_silent_context()
        self.inventory = demo.generate_inventory(**demo.FULLHA)

    def test_patch_inventory(self):
        def inventory_action(resources_: res.DynamicResources):
            resources_.inventory()['p'] = 'v'

        action_ = test_utils.new_action('test', action=inventory_action, recreate_inventory=True)

        inventory = {
            'nodes': [{'roles': ['control-plane'], 'internal_address': '1.1.1.1', 'keyfile': '/dev/null'}]
        }
        resources = demo.new_resources(inventory)
        flow.ActionsFlow([action_]).run_flow(resources, print_summary=False)
        self.assertEqual('v', resources.inventory()['p'])

    def test_patch_cluster(self):
        def cluster_action(resources_: res.DynamicResources):
            resources_.cluster().nodes['all'].sudo('whoami')

        action_ = test_utils.new_action('test', action=cluster_action)

        hosts = [node["address"] for node in self.inventory["nodes"]]
        result = demo.create_hosts_result(hosts, stdout='root')
        fake_shell = demo.FakeShell()
        fake_shell.add(result, 'sudo', ['whoami'])

        resources = demo.FakeResources(self.context, self.inventory,
                                       nodes_context=demo.generate_nodes_context(self.inventory),
                                       fake_shell=fake_shell)
        flow.ActionsFlow([action_]).run_flow(resources, print_summary=False)
        for host in hosts:
            history = fake_shell.history_find(host, 'sudo', ['whoami'])
            self.assertTrue(len(history) == 1 and history[0]["used_times"] == 1)

        self.assertEqual(['test'], resources.context['successfully_performed'])


class FakeResources(test_utils.FakeResources):
    def __init__(self, context: dict, nodes_context: dict):
        """Constructor intentionally lacks of inventories. They should be natively loaded from the filesystem"""
        super().__init__(context, nodes_context=nodes_context)
        args: dict = context['execution_arguments']
        self.inventory_filepath = args['config']
        self.procedure_inventory_filepath: Optional[str] = args.get('procedure_config')


class RunActionsTest(test_utils.CommonTest):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.procedure_inventory = None

    def prepare_context(self, args: list = None, procedure: str = 'install'):
        args = list(args) if args else []
        args.extend([
            '--ansible-inventory-location', os.path.join(self.tmpdir, 'ansible-inventory.ini'),
            '--dump-location', self.tmpdir,
            '-c', os.path.join(self.tmpdir, 'cluster.yaml')
        ])
        if self.procedure_inventory is not None:
            args.insert(0, os.path.join(self.tmpdir, 'procedure.yaml'))

        # pylint: disable-next=attribute-defined-outside-init
        self.context: dict = procedures.import_procedure(procedure).create_context(args)
        args = self.context['execution_arguments']

        utils.prepare_dump_directory(self.context)
        utils.dump_file(self.context, yaml.dump(self.inventory), args['config'], dump_location=False)
        if self.procedure_inventory is not None:
            utils.dump_file(self.context, yaml.dump(self.procedure_inventory), args['procedure_config'], dump_location=False)

    def _new_resources(self) -> demo.FakeResources:
        return FakeResources(self.context, nodes_context=demo.generate_nodes_context(self.inventory))

    def _run_actions(self, actions: List[action.Action],
                     resources: res.DynamicResources = None,
                     exception_message: str = None) -> List[str]:
        if resources is None:
            resources = self._new_resources()
        if exception_message is None:
            flow.run_actions(resources, actions)
        else:
            with test_utils.assert_raises_regex(self, Exception, exception_message):
                flow.run_actions(resources, actions)

        return resources.cluster(EnrichmentStage.LIGHT).uploaded_archives

    def _check_local_archive(self, local_archive_path: str, files: Set[str]):
        self.assertTrue(os.path.isfile(local_archive_path), f"Local archive {local_archive_path} does not exist")
        with tarfile.open(local_archive_path, "r:gz") as tar:
            self.assertEqual(files, set(tar.getnames()))

    def _extract(self, local_archive_path: str, file) -> str:
        with tarfile.open(local_archive_path, "r:gz") as tar:
            return tar.extractfile(file).read().decode('utf-8')

    def _prepare_action(self, action_: flow.TasksAction, tasks: dict = None) -> flow.TasksAction:
        if tasks is None:
            tasks = {}

        action_.tasks = collections.OrderedDict(tasks)
        return action_

    def _list_dump_content(self) -> Set[str]:
        dump_location = os.path.join(self.tmpdir, 'dump')
        if os.path.exists(dump_location):
            return set(os.listdir(dump_location))

        return set()

    def test_install_action_preserve_inventory(self):
        for disable_dump in (False, True):
            with self.subTest(f"Disable dump: {disable_dump}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                args = []
                if disable_dump:
                    args.append('--disable-dump')
                self.prepare_context(args, procedure='install')

                uploaded_archives = self._run_actions([self._prepare_action(install.InstallAction())])
                self.assertEqual(1, len(uploaded_archives))

                self._check_local_archive(
                    uploaded_archives[0],
                    {'dump/procedure_parameters',
                     'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
                     'cluster.yaml', 'version'})

                expected_dump_content = set(utils.ClusterStorage.PRESERVED_DUMP_FILES) \
                                        - {'procedure.yaml'} | {'local.tar.gz'}
                actual_dump_content = self._list_dump_content()
                self.assertFalse(expected_dump_content - actual_dump_content)

    def test_install_action_disable_dump(self):
        for without_act in (False, True):
            with self.subTest(f"Without act: {without_act}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                args = ['--disable-dump']
                if without_act:
                    args.append('--without-act')
                self.prepare_context(args, procedure='install')

                uploaded_archives = self._run_actions([self._prepare_action(install.InstallAction())])
                self.assertEqual(without_act, len(uploaded_archives) == 0)

                if without_act:
                    expected_dump_content = set()
                else:
                    expected_dump_content = set(utils.ClusterStorage.PRESERVED_DUMP_FILES) \
                                            - {'procedure.yaml'} | {'local.tar.gz'}

                actual_dump_content = self._list_dump_content()
                self.assertEqual(expected_dump_content, actual_dump_content)

    @test_utils.temporary_directory
    def test_cluster_finalized_disable_dump_without_act(self):
        self.prepare_context(['--disable-dump', '--without-act'], procedure='install')

        with test_utils.chdir(self.tmpdir):
            resources = test_utils.PackageStubResources(
                self.context, nodes_context=demo.generate_nodes_context(self.inventory))

            self._run_actions([self._prepare_action(install.InstallAction())],
                              resources=resources)

        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, 'cluster_finalized.yaml')))

    @test_utils.temporary_directory
    def test_install_action_failed_task(self):
        self.prepare_context(procedure='install')

        def failed_task(_: demo.FakeKubernetesCluster):
            raise Exception("test")

        uploaded_archives = self._run_actions([
            self._prepare_action(install.InstallAction(), {"test": failed_task}),
        ], exception_message="test")
        self.assertEqual(0, len(uploaded_archives))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'cluster.yaml')))
        self.assertFalse(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'cluster_finalized.yaml')))

    @test_utils.temporary_directory
    def test_upgrade_templates_two_versions(self):
        before, through, after = 'v1.26.11', 'v1.27.13', 'v1.28.9'
        self.inventory['values'] = {
            'before': before, 'through': through, 'after': after,
        }
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': '{{ values.before }}'
        }
        self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
        upgrade_plan = ['{{ values.through }}', '{{ values.after }}']
        self.procedure_inventory['upgrade_plan'] = upgrade_plan

        self.prepare_context(procedure='upgrade')
        uploaded_archives = self._run_actions([self._prepare_action(upgrade.UpgradeAction(version, i))
                                             for i, version in enumerate(upgrade_plan)])
        self.assertEqual(2, len(uploaded_archives))
        archive_content = {
            'dump/procedure_parameters', 'dump/procedure.yaml',
            'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
            'cluster.yaml', 'version'
        }
        self._check_local_archive(uploaded_archives[0], archive_content)
        self._check_local_archive(uploaded_archives[1], archive_content)

        self.assertEqual({'debug.log', through, after}, self._list_dump_content())

        for i in range(2):
            procedure_parameters = yaml.safe_load(self._extract(uploaded_archives[i], 'dump/procedure_parameters'))
            version = [through, after][i]
            self.assertEqual([f'upgrade to {version}'], procedure_parameters.get('successfully_performed', []))

    @test_utils.temporary_directory
    def test_upgrade_templates_second_version_failed_task(self):
        before, through, after = 'v1.26.11', 'v1.27.13', 'v1.28.9'
        self.inventory['values'] = {
            'before': before, 'through': through, 'after': after,
        }
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': '{{ values.before }}'
        }
        self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
        upgrade_plan = ['{{ values.through }}', '{{ values.after }}']
        self.procedure_inventory['upgrade_plan'] = upgrade_plan

        self.prepare_context(procedure='upgrade')

        def failed_task(_: demo.FakeKubernetesCluster):
            raise Exception("test")

        uploaded_archives = self._run_actions([
            self._prepare_action(upgrade.UpgradeAction(upgrade_plan[0], 0)),
            self._prepare_action(upgrade.UpgradeAction(upgrade_plan[1], 1), {"test": failed_task}),
        ], exception_message="test")
        self.assertEqual(1, len(uploaded_archives))
        self._check_local_archive(
            uploaded_archives[0],
            {'dump/procedure_parameters', 'dump/procedure.yaml',
             'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
             'cluster.yaml', 'version'})

        self.assertEqual({'debug.log', through, after}, self._list_dump_content())
        for i, version in enumerate((through, after)):
            self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'dump', version, 'cluster.yaml')))
            finalized_inventory_dumped = [True, False][i]
            self.assertEqual(finalized_inventory_dumped,
                             os.path.isfile(os.path.join(self.tmpdir, 'dump', version, 'cluster_finalized.yaml')))

    @test_utils.temporary_directory
    def test_upgrade_failed_enrichment(self):
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': 'v1.26.11'
        }
        self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
        self.procedure_inventory['upgrade_plan'] = ['v1.27.13']

        self._run_upgrade_with_failed_enrichment(version_verified=False)

        dump_content = {'debug.log', 'v1.27.13'}
        self.assertEqual(dump_content, self._list_dump_content())
        self.assertFalse(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'v1.27.13', 'cluster.yaml')))
        self.assertFalse(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'v1.27.13', 'cluster_finalized.yaml')))

    def test_upgrade_templates_failed_enrichment(self):
        for verified in (False, True):
            with self.subTest(f"version verified: {verified}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {
                    'before': 'v1.26.11', 'after': 'v1.27.13'
                }
                self.inventory['services']['kubeadm'] = {
                    'kubernetesVersion': '{{ values.before }}'
                }
                self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
                self.procedure_inventory['upgrade_plan'] = ['{{ values.after }}']

                self._run_upgrade_with_failed_enrichment(version_verified=verified)

                dump_subdir = 'upgrade'
                if verified:
                    dump_subdir = 'v1.27.13'

                dump_content = {'debug.log', dump_subdir}
                self.assertEqual(dump_content, self._list_dump_content())
                self.assertFalse(os.path.isfile(os.path.join(self.tmpdir, 'dump', dump_subdir, 'cluster.yaml')))
                self.assertFalse(os.path.isfile(os.path.join(self.tmpdir, 'dump', dump_subdir, 'cluster_finalized.yaml')))

    def _run_upgrade_with_failed_enrichment(self, *, version_verified: bool):
        self.prepare_context(procedure='upgrade')

        def enrichment_failed(_: KubernetesCluster) -> None:
            raise Exception("test")

        resources = self._new_resources()
        resources.insert_enrichment_function(
            kubernetes.verify_upgrade_inventory, EnrichmentStage.PROCEDURE, enrichment_failed,
            procedure='upgrade', after=version_verified)
        upgrade_plan = self.procedure_inventory['upgrade_plan']
        uploaded_archives = self._run_actions(
            [self._prepare_action(upgrade.UpgradeAction(upgrade_plan[0], 0))],
            resources, exception_message="test")
        self.assertEqual(0, len(uploaded_archives))

    @test_utils.temporary_directory
    def test_upgrade_formatted_procedure_inventory(self):
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': 'v1.26.11'
        }
        procedure_inventory_text = dedent("""\
            upgrade_plan:
              # comment
              - "v1.27.13"
        """)
        self.procedure_inventory = yaml.safe_load(procedure_inventory_text)
        upgrade_plan = self.procedure_inventory['upgrade_plan']

        self.prepare_context(procedure='upgrade')
        # Dump formatted inventory with original quotes, comments, and indentation
        args = self.context['execution_arguments']
        utils.dump_file(self.context, procedure_inventory_text, args['procedure_config'], dump_location=False)

        resources = self._new_resources()

        self._run_actions([self._prepare_action(upgrade.UpgradeAction(upgrade_plan[0], 0))],
                          resources=resources)

        buf = io.StringIO()
        utils.yaml_structure_preserver().dump(resources.inventory(), buf)
        self.assertIn(f'kubernetesVersion: "{upgrade_plan[0]}"', buf.getvalue())

    def test_check_collect_test_cases(self):
        for i, procedure in enumerate(('check_iaas', 'check_paas')):
            with self.subTest(f"procedure: {procedure}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.prepare_context(procedure=procedure)

                def test_case(cluster: demo.FakeKubernetesCluster):
                    with testsuite.TestCase(cluster, '001', 'TC Category', 'TC Name') as tc:
                        tc.success('TC result')

                check_action = [check_iaas.IaasAction(), check_paas.PaasAction()][i]
                self._prepare_action(check_action, {'test': test_case})

                resources = self._new_resources()
                result = flow.ActionsFlow([check_action]).run_flow(resources, print_summary=False)
                uploaded_archives = resources.cluster(EnrichmentStage.LIGHT).uploaded_archives

                self.assertEqual(0, len(uploaded_archives),
                                 "Check procedures should not preserve inventory")

                self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'cluster.yaml')))
                self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, 'dump', 'cluster_finalized.yaml')))

                self.assertIn('testsuite', result.context)
                testsuite_: testsuite.TestSuite = result.context['testsuite']
                self.assertEqual(1, len(testsuite_.tcs))
                self.assertEqual({'succeeded': 1}, testsuite_.get_stats_data())
                self.assertEqual(True, testsuite_.tcs[0].is_succeeded())

                result_context = result.context.get('summary_report', {})
                self.assertNotIn(summary.SummaryItem.EXECUTION_TIME, result_context)

    def test_run_two_cluster_actions_collect_summary(self):
        for recreate_inventory in (False, True):
            with self.subTest(f"inventory recreated: {recreate_inventory}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {}
                self.prepare_context(procedure='migrate_kubemarine')

                def enrich_inventory_from_context(cluster: KubernetesCluster) -> None:
                    if 'enrich_inventory_from_context' in cluster.context:
                        cluster.inventory['values']['property'] = cluster.context['enrich_inventory_from_context']

                resources = self._new_resources()
                resources.insert_enrichment_function(schema.verify_inventory, EnrichmentStage.PROCEDURE,
                                                     enrich_inventory_from_context,
                                                     procedure='migrate_kubemarine')

                def get_action_summary(property_: summary.SummaryItem, value: str, recreate_inventory=recreate_inventory):
                    def action_summary(resources_: res.DynamicResources):
                        if recreate_inventory:
                            resources_.cluster(EnrichmentStage.DEFAULT)
                            resources_.context['enrich_inventory_from_context'] = property_.text
                            resources_.reset_cluster(EnrichmentStage.DEFAULT)
                            cluster = resources_.cluster(EnrichmentStage.PROCEDURE)
                            self.assertEqual(property_.text, cluster.inventory['values']['property'])
                        else:
                            cluster = resources_.cluster()
                            self.assertNotIn('property', cluster.inventory['values'])

                        summary.schedule_report(cluster.context, property_, value)

                    return action_summary

                result = flow.ActionsFlow([
                    test_utils.new_action("test_cluster1",
                                          action=get_action_summary(summary.SummaryItem.DASHBOARD_URL, 'http://dashboard'),
                                          recreate_inventory=recreate_inventory),
                    test_utils.new_action("test_cluster2",
                                          action=get_action_summary(summary.SummaryItem.KUBECONFIG, '/path/to/kubeconfig'),
                                          recreate_inventory=recreate_inventory)
                ]).run_flow(resources)

                result_context = result.context.get('summary_report', {})
                self.assertEqual('http://dashboard', result_context.get(summary.SummaryItem.DASHBOARD_URL))
                self.assertEqual('/path/to/kubeconfig', result_context.get(summary.SummaryItem.KUBECONFIG))
                self.assertIn(summary.SummaryItem.EXECUTION_TIME, result_context)

    @test_utils.temporary_directory
    def test_run_two_cluster_actions_second_failed(self):
        self.prepare_context(procedure='migrate_kubemarine')

        def failed_action(_: res.DynamicResources):
            raise Exception("test")

        uploaded_archives = self._run_actions([
            test_utils.new_action("test_cluster1", action=lambda resources: resources.cluster()),
            test_utils.new_action("test_cluster2", action=failed_action),
        ], exception_message="test")
        self.assertEqual(1, len(uploaded_archives))
        self._check_local_archive(
            uploaded_archives[0],
            {'dump/procedure_parameters',
             'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
             'cluster.yaml', 'version'})

    def test_inventory_action_succeeded_cluster_action_failed_enrichment(self):
        for recreate_inventory in (False, True):
            with self.subTest(f"inventory recreated: {recreate_inventory}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {'k': 'v1'}
                self.prepare_context(procedure='migrate_kubemarine')

                def default_enrichment_failed(_: KubernetesCluster) -> None:
                    raise Exception("test")

                resources = demo.FakeClusterResources(
                        self.context, nodes_context=demo.generate_nodes_context(self.inventory))
                resources.insert_enrichment_function(schema.verify_inventory, EnrichmentStage.FULL, default_enrichment_failed)

                def inventory_action(resources_: res.DynamicResources, recreate_inventory=recreate_inventory):
                    if recreate_inventory:
                        resources_.inventory().setdefault('values', {})['k'] = 'v2'

                def cluster_action(resources_: res.DynamicResources):
                    resources_.cluster()

                with test_utils.chdir(self.tmpdir):
                    uploaded_archives = self._run_actions([
                        test_utils.new_action("test_inventory1", action=inventory_action, recreate_inventory=recreate_inventory),
                        test_utils.new_action("test_cluster1", action=cluster_action),
                    ], resources, exception_message="test")

                self.assertEqual(1, len(uploaded_archives))
                self._check_local_archive(
                    uploaded_archives[0],
                    {'dump/procedure_parameters',
                     'dump/cluster_initial.yaml',
                     'cluster.yaml', 'version'})

                inventory_string = self._extract(uploaded_archives[0], 'cluster.yaml')
                inventory = yaml.safe_load(inventory_string)
                expected_value = 'v2' if recreate_inventory else 'v1'
                self.assertEqual(expected_value, inventory['values']['k'])

                expected_dump_content = set(utils.ClusterStorage.PRESERVED_DUMP_FILES) \
                                        - {'procedure.yaml', 'cluster.yaml', 'cluster_finalized.yaml'} | {'local.tar.gz'}
                actual_dump_content = self._list_dump_content()
                self.assertFalse(expected_dump_content - actual_dump_content)

    def test_inventory_action_succeeded_cluster_action_failed(self):
        for recreate_inventory in (False, True):
            with self.subTest(f"inventory recreated: {recreate_inventory}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {'k': 'v1'}
                self.prepare_context(procedure='migrate_kubemarine')

                def inventory_action(resources_: res.DynamicResources, recreate_inventory=recreate_inventory):
                    if recreate_inventory:
                        resources_.inventory().setdefault('values', {})['k'] = 'v2'

                def cluster_action(resources_: res.DynamicResources):
                    resources_.cluster()
                    raise Exception("test")

                resources = demo.FakeClusterResources(
                        self.context, nodes_context=demo.generate_nodes_context(self.inventory))

                with test_utils.chdir(self.tmpdir):
                    uploaded_archives = self._run_actions([
                        test_utils.new_action("test_inventory1", action=inventory_action, recreate_inventory=recreate_inventory),
                        test_utils.new_action("test_cluster1", action=cluster_action),
                    ], resources, exception_message="test")

                self.assertEqual(1, len(uploaded_archives))
                self._check_local_archive(
                    uploaded_archives[0],
                    {'dump/procedure_parameters',
                     'dump/cluster_initial.yaml',
                     'cluster.yaml', 'version'})

                inventory_string = self._extract(uploaded_archives[0], 'cluster.yaml')
                inventory = yaml.safe_load(inventory_string)
                expected_value = 'v2' if recreate_inventory else 'v1'
                self.assertEqual(expected_value, inventory['values']['k'])

                expected_dump_content = set(utils.ClusterStorage.PRESERVED_DUMP_FILES) \
                                        - {'procedure.yaml', 'cluster_finalized.yaml'} | {'local.tar.gz'}
                actual_dump_content = self._list_dump_content()
                self.assertFalse(expected_dump_content - actual_dump_content)

    def test_procedure_enrich_inventory_dump_cluster_state(self):
        for sequential in (False, True):
            with self.subTest(f"sequential enrichment: {sequential}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {'k': 'v1'}
                self.inventory['services']['kubeadm'] = {
                    'kubernetesVersion': 'v1.26.11'
                }
                self.procedure_inventory = demo.generate_procedure_inventory('upgrade')
                self.procedure_inventory['upgrade_plan'] = ['v1.27.13']
                self.prepare_context(procedure='upgrade')
                self.context['upgrade_step'] = 0

                def enrich_inventory(cluster: KubernetesCluster) -> None:
                    cluster.inventory.setdefault('values', {})['k'] = 'v2'

                resources = self._new_resources()
                resources.insert_enrichment_function(schema.verify_inventory, EnrichmentStage.PROCEDURE,
                                                     enrich_inventory,
                                                     procedure='upgrade')

                def cluster_action(resources_: res.DynamicResources, sequential=sequential):
                    if sequential:
                        resources_.cluster(EnrichmentStage.DEFAULT)

                    cluster = resources_.cluster(EnrichmentStage.PROCEDURE)
                    self.assertEqual('v2', cluster.inventory['values']['k'])

                uploaded_archives = self._run_actions([
                    test_utils.new_action("test_cluster", action=cluster_action, recreate_inventory=True),
                ], resources)
                self.assertEqual(1, len(uploaded_archives))
                self._check_local_archive(
                    uploaded_archives[0],
                    {'dump/procedure_parameters', 'dump/procedure.yaml',
                     'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
                     'cluster.yaml', 'version'})

                for filename in ('dump/cluster.yaml', 'dump/cluster_finalized.yaml'):
                    inventory_string = self._extract(uploaded_archives[0], filename)
                    inventory = yaml.safe_load(inventory_string)
                    self.assertEqual('v2', inventory['values']['k'])

    def test_second_action_failed_dump_cluster_state_previous_action(self):
        for stage in (EnrichmentStage.DEFAULT, EnrichmentStage.PROCEDURE):
            with self.subTest(f"stage: {stage}"), test_utils.temporary_directory(self):
                self.inventory = demo.generate_inventory(**demo.ALLINONE)
                self.inventory['values'] = {'k': 'v1'}
                self.prepare_context(procedure='migrate_kubemarine')

                def enrich_inventory_from_context(cluster: KubernetesCluster) -> None:
                    if cluster.context.get('enrich_inventory_from_context', False):
                        cluster.inventory.setdefault('values', {})['k'] = 'v2'

                resources = self._new_resources()
                resources.insert_enrichment_function(schema.verify_inventory, EnrichmentStage.PROCEDURE,
                                                     enrich_inventory_from_context,
                                                     procedure='migrate_kubemarine')

                def cluster_successful_action(resources_: res.DynamicResources, stage=stage):
                    cluster = resources_.cluster(stage)
                    self.assertEqual('v1', cluster.inventory['values']['k'])

                def cluster_failed_action(resources_: res.DynamicResources):
                    resources_.cluster(EnrichmentStage.DEFAULT)
                    resources_.context['enrich_inventory_from_context'] = True
                    resources_.reset_cluster(EnrichmentStage.DEFAULT)
                    cluster = resources_.cluster(EnrichmentStage.PROCEDURE)
                    self.assertEqual('v2', cluster.inventory['values']['k'])
                    raise Exception("test")

                uploaded_archives = self._run_actions([
                    test_utils.new_action("test_cluster1", action=cluster_successful_action),
                    test_utils.new_action("test_cluster2", action=cluster_failed_action, recreate_inventory=True),
                ], resources, exception_message="test")
                self.assertEqual(1, len(uploaded_archives))
                self._check_local_archive(
                    uploaded_archives[0],
                    {'dump/procedure_parameters',
                     'dump/cluster_initial.yaml', 'dump/cluster.yaml', 'dump/cluster_finalized.yaml',
                     'cluster.yaml', 'version'})

                for filename in ('dump/cluster.yaml', 'dump/cluster_finalized.yaml'):
                    inventory_string = self._extract(uploaded_archives[0], filename)
                    inventory = yaml.safe_load(inventory_string)
                    self.assertEqual('v1', inventory['values']['k'])


class ClusterEnrichOptimization(unittest.TestCase):
    @contextmanager
    def _expected_calls(self, expected_calls: int):
        # pylint: disable-next=protected-access
        with test_utils.mock_call(defaults._compile_inventory, side_effect=defaults._compile_inventory) as run:
            try:
                yield
            finally:
                self.assertEqual(expected_calls, run.call_count, "Unexpected number of compilations")

    def test_number_of_calls_compile_inventory(self):
        for procedure, expected_calls in (
            ('add_node', 3),
            ('backup', 2),
            ('cert_renew', 3),
            ('check_iaas', 2),
            ('check_paas', 2),
            ('install', 2),
            ('manage_pss', 3),
            ('migrate_kubemarine', 3),
            ('reboot', 2),
            ('remove_node', 3),
            ('restore', 3),
            ('upgrade', 3),
        ):
            with self.subTest(procedure):
                inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
                kubernetes_version = 'v1.27.13'
                inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = kubernetes_version

                args = [] if procedure in ('check_iaas', 'install') else ['fake.yaml']
                context = demo.create_silent_context(args, procedure=procedure)
                procedure_inventory = demo.generate_procedure_inventory(procedure)

                if procedure == 'add_node':
                    procedure_inventory['nodes'] = [inventory['nodes'].pop(1)]
                elif procedure == 'remove_node':
                    procedure_inventory['nodes'] = [inventory["nodes"][1]]
                elif procedure == 'restore':
                    procedure_inventory['backup_location'] = 'fake.tar.gz'
                    context['backup_descriptor'] = {}
                elif procedure == 'upgrade':
                    procedure_inventory['upgrade_plan'] = ['v1.28.9']
                    context['upgrade_step'] = 0

                with self._expected_calls(expected_calls):
                    demo.new_cluster(inventory, procedure_inventory=procedure_inventory, context=context)

    def test_upgrade_two_versions_evolve(self):
        inventory = demo.generate_inventory(**demo.ALLINONE)
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = 'v1.27.1'

        procedure_inventory = demo.generate_procedure_inventory('upgrade')
        upgrade_plan = ['v1.27.13', 'v1.28.9']
        procedure_inventory['upgrade_plan'] = upgrade_plan

        context = demo.create_silent_context(['fake.yaml', '--without-act'], procedure='upgrade')
        with self._expected_calls(4):
            resources = demo.new_resources(inventory, procedure_inventory=procedure_inventory, context=context)
            flow.run_actions(resources, [
                upgrade.UpgradeAction(version, i) for i, version in enumerate(upgrade_plan)
            ])

    def test_migrate_kubemarine_upgrade_two_patches_evolve(self):
        # pylint: disable=protected-access

        inventory = demo.generate_inventory(**demo.ALLINONE)
        kubernetes_version = 'v1.27.13'
        inventory['services'].setdefault('kubeadm', {})['kubernetesVersion'] = kubernetes_version
        inventory['services'].setdefault('cri', {})['containerRuntime'] = 'containerd'

        nodes_context = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='22.04')

        context = demo.create_silent_context(procedure='migrate_kubemarine')

        changed_upgrade_config = {
            'packages': {
                'containerd': {'version_debian': [kubernetes_version]},
            },
            'plugins': {
                'local-path-provisioner': [kubernetes_version],
            },
        }
        with test_utils.backup_software_upgrade_config() as upgrade_config, \
                mock.patch.object(CriUpgradeAction, CriUpgradeAction._run.__name__), \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__), \
                self._expected_calls(4):
            default_merger.merge(upgrade_config, changed_upgrade_config)
            actions = [p.action for p in migrate_kubemarine.load_patches()
                       if p.identifier in ['upgrade_cri', 'upgrade_local_path_provisioner']]
            resources = demo.new_resources(inventory, context=context, nodes_context=nodes_context)
            flow.run_actions(resources, actions)


if __name__ == '__main__':
    unittest.main()
