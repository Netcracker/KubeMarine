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
import itertools
import json
import os
import re
import unittest
from copy import deepcopy
from typing import List, Set
from unittest import mock
from test.unit import utils

import yaml
from ordered_set import OrderedSet

from kubemarine import kubernetes, system, plugins, thirdparties
from kubemarine.core import errors, utils as kutils, static, log, flow, schema
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage
from kubemarine.kubernetes import components
from kubemarine.procedures import upgrade, install
from kubemarine import demo


def get_kubernetes_versions() -> List[str]:
    k8s_versions = list(static.KUBERNETES_VERSIONS['compatibility_map'])
    return sorted(k8s_versions, key=kutils.version_key)


def get_plugin_versions(plugin: str) -> List[str]:
    return list(OrderedSet([static.KUBERNETES_VERSIONS['compatibility_map'][v][plugin]
                            for v in get_kubernetes_versions()]))


class UpgradeVerifyUpgradePlan(unittest.TestCase):
    logger: log.EnhancedLogger = None

    @classmethod
    def setUpClass(cls):
        cls.logger = demo.new_cluster(demo.generate_inventory(**demo.ALLINONE)).log

    def test_valid_upgrade_plan(self):
        upgrade.verify_upgrade_plan(self.k8s_versions()[0], self.latest_patch_k8s_versions()[1:], self.logger)

    def test_invalid_upgrade_plan(self):
        k8s_oldest = self.k8s_versions()[0]
        k8s_latest = self.k8s_versions()[-1]
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (re.escape(k8s_oldest), re.escape(k8s_latest))):
            upgrade.verify_upgrade_plan(k8s_oldest, [k8s_latest], self.logger)

    def test_upgrade_plan_not_supported_version(self):
        k8s_latest = self.k8s_versions()[-1]
        not_allowed_version = utils.increment_version(k8s_latest)
        with utils.assert_raises_kme(self, "KME0008",
                                     version=re.escape(not_allowed_version),
                                     allowed_versions='.*'):
            upgrade.verify_upgrade_plan(k8s_latest, [not_allowed_version], self.logger)

    def test_incorrect_inventory_high_range(self):
        old_kubernetes_version = 'v1.28.9'
        new_kubernetes_version = 'v1.30.1'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version], self.logger)

    def test_incorrect_inventory_downgrade(self):
        old_kubernetes_version = 'v1.30.1'
        new_kubernetes_version = 'v1.29.4'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_DOWNGRADE
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version], self.logger)

    def test_incorrect_inventory_same_version(self):
        old_kubernetes_version = 'v1.30.1'
        new_kubernetes_version = 'v1.30.1'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_SAME
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version], self.logger)

    def test_incorrect_inventory_not_latest_patch_version(self):
        old_kubernetes_version = 'v1.27.1'
        new_kubernetes_version = 'v1.28.0'
        latest_supported_patch_version = next(v for v in self.latest_patch_k8s_versions()
                                              if kutils.minor_version(v) == kutils.minor_version(new_kubernetes_version))
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_NOT_LATEST_PATCH
                                               % (re.escape(new_kubernetes_version), re.escape(latest_supported_patch_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version], self.logger)

    def test_verify_templates(self):
        old_kubernetes_version = '{{ values.old }}'
        new_kubernetes_version = '{{ values.new }}'
        # no error
        upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version], self.logger)

    def test_verify_old_template_new_not_allowed(self):
        old_kubernetes_version = '{{ env.KUBERNETES_VERSION }}'
        k8s_latest = self.k8s_versions()[-1]
        not_allowed_version = utils.increment_version(k8s_latest)
        with utils.assert_raises_kme(self, "KME0008",
                                     version=re.escape(not_allowed_version),
                                     allowed_versions='.*'):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [k8s_latest, not_allowed_version], self.logger)

    def k8s_versions(self) -> List[str]:
        return get_kubernetes_versions()

    def latest_patch_k8s_versions(self) -> List[str]:
        return [sorted(versions, key=kutils.version_key)[-1]
                for _, versions in itertools.groupby(self.k8s_versions(), key=kutils.minor_version)]


class _AbstractUpgradeEnrichmentTest(unittest.TestCase):
    def setUpVersions(self, old: str, _new: List[str]):
        # pylint: disable=attribute-defined-outside-init

        self.old = old
        self.upgrade_plan = _new
        self.inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        self.inventory['services']['kubeadm'] = {
            'kubernetesVersion': old
        }
        self.context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='upgrade')
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.upgrade = demo.generate_procedure_inventory('upgrade')
        self.upgrade['upgrade_plan'] = _new
        for new in _new:
            self.upgrade[new] = {}

        self.fake_shell = demo.FakeShell()
        self.fake_fs = demo.FakeFS()

    @property
    def new(self) -> str:
        if len(self.upgrade_plan) != 1:
            raise ValueError("Multiple upgrade versions")

        return self.upgrade_plan[0]

    def new_resources(self) -> demo.FakeResources:
        return utils.FakeResources(self.context, self.inventory,
                                   procedure_inventory=self.upgrade, nodes_context=self.nodes_context,
                                   fake_shell=self.fake_shell, fake_fs=self.fake_fs)

    def run_actions(self) -> demo.FakeResources:
        resources = self.new_resources()
        actions = [upgrade.UpgradeAction(version, i) for i, version in enumerate(self.upgrade_plan)]
        flow.run_actions(resources, actions)
        return resources

    def new_cluster(self):
        self.context['upgrade_step'] = 0
        return demo.new_cluster(self.inventory, procedure_inventory=self.upgrade,
                                context=self.context, nodes_context=self.nodes_context)


class UpgradeDefaultsEnrichment(_AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.29.4', ['v1.30.1'])

    def test_correct_inventory(self):
        cluster = self.new_cluster()
        self.assertEqual(self.new, cluster.inventory['services']['kubeadm']['kubernetesVersion'])

    def test_upgrade_with_default_admission(self):
        # Upgrade PSS->PSS kuber version
        old_kubernetes_version = 'v1.25.2'
        new_kubernetes_version = 'v1.25.7'
        self.setUpVersions(old_kubernetes_version, [new_kubernetes_version])
        cluster = self.new_cluster()
        self.assertEqual("pss", cluster.inventory['rbac']['admission'])

    def test_incorrect_disable_eviction(self):
        self.upgrade['disable-eviction'] = 'true'
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'string'\. Expected: 'boolean'\."):
            self.new_cluster()

    def test_unexpected_properties(self):
        self.upgrade['unexpected-property'] = {}
        with self.assertRaisesRegex(Exception, re.escape(kubernetes.ERROR_UPGRADE_UNEXPECTED_PROPERTY % (
                "'unexpected-property'",))):
            self.new_cluster()

    def test_version_upgrade_not_possible_template(self):
        old_kubernetes_version = 'v1.27.1'
        new_kubernetes_version = 'v1.28.0'
        latest_supported_patch_version = max(
            (v for v in static.KUBERNETES_VERSIONS['compatibility_map']
             if kutils.minor_version(v) == kutils.minor_version(new_kubernetes_version)),
            key=kutils.version_key
        )
        self.setUpVersions('{{ values.before }}', ['{{ values.after }}'])
        self.inventory['values'] = {
            'before': old_kubernetes_version, 'after': new_kubernetes_version,
        }
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_NOT_LATEST_PATCH
                                               % (re.escape(new_kubernetes_version), re.escape(latest_supported_patch_version))):
            self.new_cluster()

    def test_failed_enrichment_raise_original_exception(self):
        old_kubernetes_version = 'v1.29.4'
        new_kubernetes_version = 'v1.30.1'

        for stage in (EnrichmentStage.LIGHT, EnrichmentStage.FULL, EnrichmentStage.PROCEDURE):
            with self.subTest(f"stage: {stage.name}"):
                self.setUpVersions('{{ values.before }}', ['{{ values.after }}'])
                self.inventory['values'] = {
                    'before': old_kubernetes_version, 'after': new_kubernetes_version,
                }

                exc = None
                try:
                    def enrichment_failed(_: KubernetesCluster) -> None:
                        raise Exception("test")

                    resources = self.new_resources()
                    procedure = None if stage == EnrichmentStage.FULL else 'upgrade'
                    resources.insert_enrichment_function(
                        schema.verify_inventory, stage, enrichment_failed, procedure=procedure)
                    flow.run_actions(resources, [upgrade.UpgradeAction(self.upgrade_plan[0], 0)])
                except errors.FailException as e:
                    exc = e

                self.assertIsNotNone(exc, "FailException not raised")
                reason = exc.reason
                self.assertIsNotNone(reason, "FailException has empty reason")
                self.assertIsNone(reason.__context__, "The reason is not an original exception")


class UpgradePackagesEnrichment(_AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.29.4', ['v1.30.1'])

    def setUpVersions(self, old: str, _new: List[str]):
        super().setUpVersions(old, _new)
        self.setUpNodesContext('ubuntu', '20.04')

    def setUpNodesContext(self, os_name: str, os_version: str):
        # pylint: disable-next=attribute-defined-outside-init
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)

        associations = {}
        for sample_package in ('containerd',):
            associations[sample_package] = {}

        for new in self.upgrade_plan:
            self.upgrade[new]['packages'] = {
                'associations': deepcopy(associations)
            }

        for sample_package in ('haproxy', 'keepalived', 'audit', 'conntrack'):
            associations[sample_package] = {}

        os_family = system.detect_os_family_by_name_version(os_name, os_version)
        associations[os_family] = deepcopy(associations)

        self.inventory['services']['packages'] = {
            'associations': deepcopy(associations),
        }

    def _patch_globals(self, package: str, os_family: str, *, equal=False):
        package_compatibility = static.GLOBALS['compatibility_map']['software'][package]
        package_compatibility[self.old][f"version_{os_family}"] = f'{package}-initial'
        if equal:
            package_compatibility[self.new][f"version_{os_family}"] = f'{package}-initial'
        else:
            package_compatibility[self.new][f"version_{os_family}"] = f'{package}-new'

    def test_enrich_packages_propagate_associations(self):
        self.upgrade[self.new]['packages']['associations']['containerd']['package_name'] = 'containerd'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self.new_cluster()
        self.assertEqual(['curl'], cluster.inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        actual_package = cluster.inventory['services']['packages']['associations']['debian']['containerd']['package_name']
        self.assertEqual('containerd', actual_package,
                         "Associations packages are enriched incorrectly")

    def test_final_inventory_enrich_global(self):
        self.upgrade[self.new]['packages']['associations']['containerd']['package_name'] = 'containerd'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self.new_cluster()
        final_inventory = cluster.formatted_inventory
        self.assertEqual(['curl'], final_inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        self.assertEqual('containerd',
                         final_inventory['services']['packages']['associations']['containerd']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_require_package_redefinition(self):
        for global_section in (False, True):
            with self.subTest(f"global: {global_section}"), \
                    utils.backup_globals(), \
                    utils.assert_raises_kme(self, "KME0010", package='containerd',
                                            previous_version_spec='.*', next_version_spec='.*'):
                self._patch_globals('containerd', 'debian', equal=True)

                self.setUp()
                associations = self.inventory['services']['packages']['associations']
                if not global_section:
                    associations = associations['debian']
                associations['containerd']['package_name'] = 'containerd-redefined'

                self.new_cluster()

    def test_dont_require_package_redefinition_does_not_support_upgrade(self):
        for package in ('haproxy', 'keepalived', 'audit', 'conntrack'):
            for global_section in (False, True):
                with self.subTest(f"package: {package}, global: {global_section}"):
                    self.setUp()
                    associations = self.inventory['services']['packages']['associations']
                    if not global_section:
                        associations = associations['debian']
                    associations[package]['package_name'] = f'{package}-redefined'

                    # no error
                    self.new_cluster()

    def test_require_package_redefinition_version_templates(self):
        before, through1, through2, after = 'v1.26.3', 'v1.26.11', 'v1.27.13', 'v1.28.9'
        for template in (False, True):
            with self.subTest(f"template: {template}"), \
                    utils.assert_raises_kme(
                        self, "KME0010", escape=True,
                        package='containerd',
                        previous_version_spec=f' for version {through2}',
                        next_version_spec=f' for version {after}'):
                target_version = after if not template else '{{ values.after }}'
                self.setUpVersions('{{ values.before }}',
                                   ['{{ values.through1 }}', '{{ values.through2 }}', target_version])
                self.inventory['values'] = {
                    'before': before, 'through1': through1, 'through2': through2,
                }
                if template:
                    self.inventory['values']['after'] = after
                self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-redefined'
                self.upgrade['{{ values.through1 }}']['packages']['associations']\
                    ['containerd']['package_name'] = 'containerd-upgrade1'
                self.upgrade['{{ values.through2 }}']['packages']['associations']\
                    ['containerd']['package_name'] = 'containerd-upgrade2'

                self.run_actions()

    def test_require_package_redefinition_first_step(self):
        self.setUpVersions('v1.26.3', ['v1.26.11', 'v1.27.13'])
        self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-redefined'
        self.upgrade[self.upgrade_plan[0]]['packages']['associations']['containerd']['package_name'] = 'containerd-upgrade1'

        with utils.assert_raises_kme(
                self, "KME0010", escape=True,
                package='containerd',
                previous_version_spec=f' for version {self.upgrade_plan[0]}',
                next_version_spec=f' for version {self.upgrade_plan[1]}'):
            flow.run_actions(self.new_resources(), [upgrade.UpgradeAction(self.upgrade_plan[0], 0)])

    def test_compatibility_upgrade_required(self):
        for os_name, os_family, os_version in (
                ('ubuntu', 'debian', '20.04'),
                ('centos', 'rhel', '7.9'),
                ('rhel', 'rhel8', '8.7'),
                ('rhel', 'rhel9', '9.2')
        ):
            for package_vary in ('containerd', 'containerdio'):
                expected_upgrade_required = package_vary in self._packages_for_cri_os_family(os_family)

                with self.subTest(f"{os_family}, {package_vary}"), utils.backup_globals():
                    self._patch_globals(package_vary, os_family, equal=False)

                    self.setUp()
                    self.setUpNodesContext(os_name, os_version)

                    cluster = self.new_cluster()
                    self.assertEqual(
                        expected_upgrade_required,
                        'containerd' in cluster.context["upgrade"]["required"]['packages'],
                        f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

    def _packages_for_cri_os_family(self, os_family: str) -> List[str]:
        if os_family in ('rhel', 'rhel8', 'rhel9'):
            package_names = ['containerdio']
        else:
            package_names = ['containerd']

        return package_names

    def test_procedure_inventory_upgrade_required_inventory_default(self):
        for procedure_associations, expected_upgrade_required in (
                (['containerd=containerd-initial'], False),
                (['containerd=containerd-new'], True),
                ('containerd-custom', True)
        ):
            with self.subTest(f"upgrade: {expected_upgrade_required}"), utils.backup_globals():
                self._patch_globals('containerd', 'debian', equal=False)

                self.setUp()
                self.upgrade[self.new]['packages']['associations']['containerd']['package_name'] = procedure_associations

                cluster = self.new_cluster()
                self.assertEqual(expected_upgrade_required,
                                 'containerd' in cluster.context["upgrade"]["required"]['packages'],
                                 f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for global_section in (False, True):
            for procedure_associations, expected_upgrade_required in (
                    ('containerd-inventory', False),
                    ('containerd-redefined', True)
            ):
                with self.subTest(f"global: {global_section}, upgrade: {expected_upgrade_required}"), \
                        utils.backup_globals():
                    self._patch_globals('containerd', 'debian', equal=True)

                    self.setUp()
                    associations = self.inventory['services']['packages']['associations']
                    if not global_section:
                        associations = associations['debian']
                    associations['containerd']['package_name'] = 'containerd-inventory'
                    self.upgrade[self.new]['packages']['associations']['containerd']['package_name'] = procedure_associations

                    cluster = self.new_cluster()
                    self.assertEqual(expected_upgrade_required,
                                     'containerd' in cluster.context["upgrade"]["required"]['packages'],
                                     f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

    def test_no_custom_packages_upgrade_not_required(self):
        self._run_upgrade_packages_and_check(False)

    def test_custom_packages_upgrade_not_required(self):
        self.inventory['services']['packages']['install'] = ['curl']
        self._run_upgrade_packages_and_check(False)

    def test_custom_packages_procedure_extended_upgrade_required(self):
        self.inventory['services']['packages']['install'] = ['curl']
        self.upgrade[self.new]['packages']['install'] = ['unzip', {'<<': 'merge'}]
        self._run_upgrade_packages_and_check(True)

    def test_custom_packages_procedure_upgrade_required(self):
        self.upgrade[self.new]['packages']['upgrade'] = ['unzip']
        self._run_upgrade_packages_and_check(True)

    def test_custom_packages_procedure_redefines_same_upgrade_required(self):
        self.inventory['services']['packages']['upgrade'] = ['curl']
        self.upgrade[self.new]['packages']['upgrade'] = ['curl']
        self._run_upgrade_packages_and_check(True)

    def _run_upgrade_packages_and_check(self, called: bool):
        args = self.context['execution_arguments']
        args['without_act'] = False
        args['tasks'] = 'packages'
        with mock.patch.object(install, install.manage_custom_packages.__name__) as run:
            self.run_actions()
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")

    def test_final_inventory_merge_packages(self):
        self.inventory['services']['packages'].setdefault('install', {})['include'] = ['curl']
        self.upgrade[self.new]['packages']['install'] = ['unzip', {'<<': 'merge'}]

        self.inventory['services']['packages'].setdefault('upgrade', {})['exclude'] = ['conntrack']
        self.upgrade[self.new]['packages'].setdefault('upgrade', {})['exclude'] = [{'<<': 'merge'}, 'socat']
        cluster = self.new_cluster()

        self.assertEqual(['unzip', 'curl'], cluster.inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], cluster.inventory['services']['packages']['upgrade']['exclude'])
        self.assertEqual(['*'], cluster.inventory['services']['packages']['upgrade']['include'])

        utils.stub_associations_packages(cluster, {})
        utils.stub_detect_packages(cluster, {"unzip": {}, "curl": {}})

        finalized_inventory = utils.make_finalized_inventory(cluster, stub_cache_packages=False)
        self.assertEqual(['unzip', 'curl'], finalized_inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], finalized_inventory['services']['packages']['upgrade']['exclude'])
        self.assertEqual(['*'], finalized_inventory['services']['packages']['upgrade']['include'])

        final_inventory = cluster.formatted_inventory
        self.assertEqual(['unzip', 'curl'], final_inventory['services']['packages']['install']['include'])
        self.assertEqual(['conntrack', 'socat'], final_inventory['services']['packages']['upgrade']['exclude'])
        self.assertIsNone(final_inventory['services']['packages']['upgrade'].get('include'))


class UpgradePluginsEnrichment(utils.CommonTest, _AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.29.4', ['v1.30.1'])

    def setUpVersions(self, old: str, _new: List[str]):
        super().setUpVersions(old, _new)
        self.inventory['plugins'] = {}
        for new in _new:
            self.upgrade[new]['plugins'] = {}

    def _patch_globals(self, plugin: str, *, equal=False, real=False):
        plugin_versions = get_plugin_versions(plugin)
        if real and not equal and len(plugin_versions) == 1:
            self.skipTest(f"Plugin {plugin} has the only version")

        old_version = (static.KUBERNETES_VERSIONS['compatibility_map'][self.old][plugin]
                       if not real else plugin_versions[0])
        plugin_compatibility = static.GLOBALS['compatibility_map']['software'][plugin]
        plugin_compatibility[self.old]["version"] = old_version
        if equal:
            plugin_compatibility[self.new]["version"] = old_version
        else:
            new_version = utils.increment_version(old_version) if not real else plugin_versions[-1]
            plugin_compatibility[self.new]["version"] = new_version

    def test_redefine_image_recursive(self):
        self.inventory['plugins'].setdefault('kubernetes-dashboard', {}).setdefault('dashboard', {})['image'] = 'A'
        self.upgrade[self.new]['plugins'].setdefault('kubernetes-dashboard', {}).setdefault('dashboard', {})['image'] = 'B'

        cluster = self.new_cluster()
        self.assertEqual('B',
                         cluster.inventory['plugins']['kubernetes-dashboard']['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

    def test_require_image_redefinition_recursive(self):
        self.inventory['plugins'].setdefault('calico', {}).setdefault('cni', {})['image'] = 'A'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0009",
                                        key='image', plugin_name='calico',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('calico', equal=True)
            self.new_cluster()

    def test_require_helper_pod_image_redefinition(self):
        self.inventory['plugins'].setdefault('local-path-provisioner', {})['helper-pod-image'] = 'A'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0009",
                                        key='helper-pod-image', plugin_name='local-path-provisioner',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('local-path-provisioner', equal=True)
            self.new_cluster()

    def test_require_version_redefinition(self):
        fake_version = static.KUBERNETES_VERSIONS['compatibility_map'][self.old]['nginx-ingress-controller']
        self.inventory['plugins'].setdefault('nginx-ingress-controller', {})['version'] = fake_version
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0009",
                                        key='version', plugin_name='nginx-ingress-controller',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('nginx-ingress-controller', equal=True)
            self.new_cluster()

    def test_require_image_redefinition_version_templates(self):
        before, through1, through2, after = 'v1.26.3', 'v1.26.11', 'v1.27.13', 'v1.28.9'
        for template in (False, True):
            with self.subTest(f"template: {template}"), \
                    utils.assert_raises_kme(
                        self, "KME0009", escape=True,
                        key='image', plugin_name='kubernetes-dashboard',
                        previous_version_spec=f' for version {through2}',
                        next_version_spec=f' for next version {after}'):
                target_version = after if not template else '{{ values.after }}'
                self.setUpVersions('{{ values.before }}',
                                   ['{{ values.through1 }}', '{{ values.through2 }}', target_version])
                self.inventory['values'] = {
                    'before': before, 'through1': through1, 'through2': through2,
                }
                if template:
                    self.inventory['values']['after'] = after

                self.inventory['plugins'].setdefault('kubernetes-dashboard', {})\
                    .setdefault('dashboard', {})['image'] = 'dashboard-redefined'
                self.upgrade['{{ values.through1 }}']['plugins'].setdefault('kubernetes-dashboard', {})\
                    .setdefault('dashboard', {})['image'] = 'dashboard-upgrade1'
                self.upgrade['{{ values.through2 }}']['plugins'].setdefault('kubernetes-dashboard', {})\
                    .setdefault('dashboard', {})['image'] = 'dashboard-upgrade2'

                self.run_actions()

    def test_require_image_redefinition_first_step(self):
        self.setUpVersions('v1.26.3', ['v1.26.11', 'v1.27.13'])
        self.inventory['plugins'].setdefault('kubernetes-dashboard', {})\
            .setdefault('dashboard', {})['image'] = 'dashboard-redefined'
        self.upgrade[self.upgrade_plan[0]]['plugins'].setdefault('kubernetes-dashboard', {})\
            .setdefault('dashboard', {})['image'] = 'dashboard-upgrade1'

        with utils.assert_raises_kme(
                self, "KME0009", escape=True,
                key='image', plugin_name='kubernetes-dashboard',
                previous_version_spec=f' for version {self.upgrade_plan[0]}',
                next_version_spec=f' for next version {self.upgrade_plan[1]}'):
            flow.run_actions(self.new_resources(), [upgrade.UpgradeAction(self.upgrade_plan[0], 0)])

    def test_compatibility_map_upgrade_required(self):
        plugin = self._get_plugin_few_versions()
        for compatibility_changed in (False, True):
            with self.subTest(f"compatibility changed: {compatibility_changed}"), \
                    utils.backup_globals():
                self._patch_globals(plugin, equal=not compatibility_changed, real=True)

                self.setUp()
                self.inventory['plugins'][plugin] = {'install': True}

                self._run_and_check(plugin, compatibility_changed)

    def test_procedure_inventory_empty_upgrade_required_default(self):
        plugin = 'nginx-ingress-controller'
        self.inventory['plugins'][plugin] = {'install': True}
        # Even empty configuration triggers re-installation
        self.upgrade[self.new]['plugins'][plugin] = {}
        with utils.backup_globals():
            self._patch_globals(plugin, equal=True)
            self._run_and_check(plugin, True)

    def test_procedure_inventory_upgrade_required_custom(self):
        for procedure_redefined in (False, True):
            with self.subTest(f"procedure redefined: {procedure_redefined}"):
                self.setUp()

                plugin = 'custom-plugin'
                self.inventory['plugins'][plugin] = {
                    'install': True,
                    'installation': {'procedures': [
                        {'shell': 'whoami'}
                    ]}
                }
                if procedure_redefined:
                    # Even empty configuration should trigger re-installation
                    self.upgrade[self.new]['plugins'][plugin] = {}

                self._run_and_check(plugin, procedure_redefined)

    def test_procedure_inventory_upgrade_required_custom_template(self):
        plugin = 'custom-plugin'
        self.inventory['plugins'][plugin] = {
            'install': True,
            'param': '{{ services.kubeadm.kubernetesVersion }}',
            'installation': {'procedures': [
                {'shell': 'whoami'}
            ]}
        }
        self._run_and_check(plugin, True)

    def test_procedure_inventory_upgrade_required_new_custom(self):
        plugin = 'custom-plugin'
        self.upgrade[self.new]['plugins'][plugin] = {
            'install': True,
            'installation': {'procedures': [
                {'shell': 'whoami'}
            ]}
        }
        self._run_and_check(plugin, True)

    def test_change_hostname_check_jinja_dependent_parameters(self):
        self.upgrade[self.new]['plugins'].setdefault('kubernetes-dashboard', {})['hostname'] = 'changed-hostname'
        cluster = self.new_cluster()

        dashboard = cluster.inventory['plugins']['kubernetes-dashboard']
        self.assertEqual('changed-hostname', dashboard['hostname'])

        ingress_spec = dashboard['ingress']['spec']
        self.assertEqual('changed-hostname', ingress_spec['tls'][0]['hosts'][0])
        self.assertEqual('changed-hostname', ingress_spec['rules'][0]['host'])

    @utils.temporary_directory
    def test_list_merge_strategy_ansible(self):
        args = self.context['execution_arguments']
        ansible_inventory_location = os.path.join(self.tmpdir, 'ansible-inventory.ini')
        args['ansible_inventory_location'] = ansible_inventory_location

        plugin = 'custom-plugin'
        self.inventory['plugins'][plugin] = {
            'install': True,
            'array': ['one'],
        }
        self.upgrade[self.new]['plugins'][plugin] = {
            'array': [{'<<': 'merge'}, 'two'],
        }

        resources = self.run_actions()

        self.assertEqual(['one', 'two'], resources.working_inventory['plugins'][plugin]['array'])
        self.assertEqual(['one', 'two'], resources.finalized_inventory['plugins'][plugin]['array'])
        self.assertEqual(['one', 'two'], resources.inventory()['plugins'][plugin]['array'])

        ansible_inventory = kutils.read_external(ansible_inventory_location)
        array = next(filter(lambda l: 'custom_plugin_array=' in l, ansible_inventory.split('\n')))
        self.assertEqual(['one', 'two'], json.loads(array[len('custom_plugin_array='):]))

    def _get_plugin_few_versions(self) -> str:
        for plugin in ('calico', 'nginx-ingress-controller', 'kubernetes-dashboard', 'local-path-provisioner'):
            if len(get_plugin_versions(plugin)) > 1:
                return plugin

        self.skipTest("All plugins have the only version")

    def _run_and_check(self, plugin: str, called: bool):
        args = self.context['execution_arguments']
        args['without_act'] = False
        args['tasks'] = 'plugins'
        with mock.patch.object(plugins, plugins.install_plugin.__name__) as run:
            self.run_actions()
            actual_called = any(call_args[0][1] == plugin for call_args in run.call_args_list)
            self.assertEqual(called, actual_called,
                             f"Upgrade of {plugin!r} was {'not' if called else 'unexpectedly'} run")


class ThirdpartiesEnrichment(_AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.29.4', ['v1.30.1'])

    def setUpVersions(self, old: str, _new: List[str]):
        super().setUpVersions(old, _new)
        self.inventory['services']['thirdparties'] = {}
        for new in _new:
            self.upgrade[new]['thirdparties'] = {}

    def _patch_globals(self, thirdparty: str, *, equal=False):
        fake_version = 'v1.2.3'
        thirdparty_compatibility = static.GLOBALS['compatibility_map']['software'][thirdparty]
        thirdparty_compatibility[self.old]["version"] = fake_version
        if equal:
            thirdparty_compatibility[self.new]["version"] = fake_version
        else:
            thirdparty_compatibility[self.new]["version"] = utils.increment_version(fake_version)

    def test_final_inventory(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubeadm'] = {
            'source': 'kubeadm-redefined',
            'sha1': 'fake-sha1'
        }
        self.inventory['services']['thirdparties']['/usr/bin/kubelet'] = 'kubelet-redefined'
        self.inventory['services']['thirdparties']['/custom1'] = 'custom1-initial'
        self.inventory['services']['thirdparties']['/custom2'] = {'source': 'custom2-initial', 'group': 'control-plane'}
        self.inventory['services']['thirdparties']['/custom3'] = 'custom3-initial'
        all_thirdparties = set(static.DEFAULTS['services']['thirdparties']) | {'/custom1', '/custom2', '/custom3'}

        self.upgrade[self.new]['thirdparties']['/usr/bin/kubeadm'] = {
            'source': 'kubeadm-new',
            'sha1': 'fake-sha1-new'
        }
        self.upgrade[self.new]['thirdparties']['/usr/bin/kubelet'] = {'source': 'kubelet-new'}
        self.upgrade[self.new]['thirdparties']['/custom1'] = 'custom1-new'
        self.upgrade[self.new]['thirdparties']['/custom2'] = 'custom2-new'

        cluster = self.new_cluster()
        thirdparties_section = cluster.inventory['services']['thirdparties']

        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubeadm-new', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertEqual('fake-sha1-new', thirdparties_section['/usr/bin/kubeadm']['sha1'])
        self.assertEqual('custom1-new', thirdparties_section['/custom1']['source'])
        self.assertEqual('custom2-new', thirdparties_section['/custom2']['source'])
        self.assertEqual(['control-plane'], thirdparties_section['/custom2']['groups'])
        self.assertEqual('custom3-initial', thirdparties_section['/custom3']['source'])

        finalized_inventory = utils.make_finalized_inventory(cluster)
        thirdparties_section = finalized_inventory['services']['thirdparties']

        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubeadm-new', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertEqual('fake-sha1-new', thirdparties_section['/usr/bin/kubeadm']['sha1'])
        self.assertEqual('custom1-new', thirdparties_section['/custom1']['source'])
        self.assertEqual('custom2-new', thirdparties_section['/custom2']['source'])
        self.assertEqual(['control-plane'], thirdparties_section['/custom2']['groups'])
        self.assertEqual('custom3-initial', thirdparties_section['/custom3']['source'])

        final_inventory = cluster.formatted_inventory
        thirdparties_section = final_inventory['services']['thirdparties']

        self.assertEqual({'/usr/bin/kubeadm', '/usr/bin/kubelet', '/custom1', '/custom2', '/custom3'},
                         set(thirdparties_section.keys()))
        self.assertEqual('kubeadm-new', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertEqual('fake-sha1-new', thirdparties_section['/usr/bin/kubeadm']['sha1'])
        self.assertEqual('custom1-new', thirdparties_section['/custom1']['source'])
        self.assertEqual('custom2-new', thirdparties_section['/custom2']['source'])
        self.assertEqual('control-plane', thirdparties_section['/custom2']['group'])
        self.assertEqual('custom3-initial', thirdparties_section['/custom3'])

    def test_enrich_upgrade_unpack(self):
        self.upgrade[self.new]['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-new'

        cluster = self.new_cluster()
        thirdparties_section = cluster.inventory['services']['thirdparties']
        self.assertEqual('crictl-new', thirdparties_section['/usr/bin/crictl.tar.gz']['source'])
        self.assertEqual('/usr/bin/', thirdparties_section['/usr/bin/crictl.tar.gz']['unpack'])

    def test_require_source_redefinition_defaults_changed(self):
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0011",
                                        key='source', thirdparty='/usr/bin/crictl.tar.gz',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('crictl', equal=False)
            self.new_cluster()

    def test_dont_require_source_redefinition_defaults_unchanged(self):
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'
        with utils.backup_globals():
            self._patch_globals('crictl', equal=True)
            # no error
            self.new_cluster()

    def test_dont_require_redefinition_source_templates(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubelet'] = 'kubelet-{{ services.kubeadm.kubernetesVersion }}'
        self.inventory['services']['thirdparties']['/usr/bin/calicoctl'] = 'calicoctl-{{ plugins.calico.version }}'
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] \
            = 'crictl-{{ globals.compatibility_map.software.crictl[services.kubeadm.kubernetesVersion].version }}'
        with utils.backup_globals():
            self._patch_globals('crictl', equal=False)

            compatibility_map = static.GLOBALS['compatibility_map']['software']

            plugin_versions = get_plugin_versions('calico')
            calico_old_version = plugin_versions[0]
            calico_new_version = plugin_versions[-1]

            compatibility_map['calico'][self.old]["version"] = calico_old_version
            compatibility_map['calicoctl'][self.old]["version"] = calico_old_version
            compatibility_map['calico'][self.new]["version"] = calico_new_version
            compatibility_map['calicoctl'][self.new]["version"] = calico_new_version

            # no error
            self.new_cluster()

    def test_dont_require_redefinition_source_template_defaults_changed_second_step(self):
        self.setUpVersions('v1.26.3', ['v1.26.11', 'v1.27.13'])
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] \
            = 'crictl-{{ globals.compatibility_map.software.crictl[services.kubeadm.kubernetesVersion].version }}'

        with utils.backup_globals():
            fake_version = 'v1.2.3'
            crictl_compatibility = static.GLOBALS['compatibility_map']['software']['crictl']
            crictl_compatibility[self.old]["version"] = fake_version
            crictl_compatibility[self.upgrade_plan[0]]["version"] = fake_version
            crictl_compatibility[self.upgrade_plan[1]]["version"] = utils.increment_version(fake_version)

            # no error
            self.new_cluster()

    def test_require_sha1_redefinition(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubectl'] = {
            'source': 'kubectl-redefined',
            'sha1': 'fake-sha1'
        }
        self.upgrade[self.new]['thirdparties']['/usr/bin/kubectl'] = 'kubectl-new'

        with utils.assert_raises_kme(self, "KME0011",
                                     key='sha1', thirdparty='/usr/bin/kubectl',
                                     previous_version_spec='.*', next_version_spec='.*'):
            self.new_cluster()

    def test_require_sha1_change_if_source_changed(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubectl'] = {
            'source': 'kubectl-redefined',
            'sha1': 'sha1-redefined'
        }
        self.upgrade[self.new]['thirdparties']['/usr/bin/kubectl'] = {
            'source': 'kubectl-new',
            'sha1': 'sha1-redefined'
        }

        with self.assertRaisesRegex(Exception, re.escape(thirdparties.ERROR_SHA1_NOT_CHANGED.format(
                thirdparty='/usr/bin/kubectl', previous_version=self.old, version=self.new))):
            self.new_cluster()

    def test_require_source_redefinition_version_templates(self):
        before, through1, through2, after = 'v1.26.3', 'v1.26.11', 'v1.27.13', 'v1.28.9'
        for template in (False, True):
            with self.subTest(f"template: {template}"), \
                    utils.assert_raises_kme(
                        self, "KME0011", escape=True,
                        key='source', thirdparty='/usr/bin/kubeadm',
                        previous_version_spec=f' for version {through2}', next_version_spec=f' for next version {after}'):
                target_version = after if not template else '{{ values.after }}'
                self.setUpVersions('{{ values.before }}',
                                   ['{{ values.through1 }}', '{{ values.through2 }}', target_version])
                self.inventory['values'] = {
                    'before': before, 'through1': through1, 'through2': through2,
                }
                if template:
                    self.inventory['values']['after'] = after
                self.inventory['services']['thirdparties']['/usr/bin/kubeadm'] = 'kubeadm-redefined'
                self.upgrade['{{ values.through1 }}']['thirdparties']['/usr/bin/kubeadm'] = {
                    'source': 'kubectl-upgrade1'
                }
                self.upgrade['{{ values.through2 }}']['thirdparties']['/usr/bin/kubeadm'] = 'kubectl-upgrade2'

                self.run_actions()


class UpgradeContainerdConfigEnrichment(_AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.25.7', ['v1.26.11'])

    def setUpVersions(self, old: str, _new: List[str]):
        super().setUpVersions(old, _new)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        self.inventory['services']['cri'].setdefault('containerdConfig', {})\
            .setdefault('plugins."io.containerd.grpc.v1.cri"', {})
        for new in _new:
            self.upgrade[new]['cri'] = {
                'containerdConfig': {
                    'plugins."io.containerd.grpc.v1.cri"': {},
                }
            }

    def _patch_globals(self, fake_version: str, *, equal=False):
        pause_compatibility = static.GLOBALS['compatibility_map']['software']['pause']
        pause_compatibility[self.old]["version"] = fake_version
        if equal:
            pause_compatibility[self.new]["version"] = fake_version
        else:
            pause_compatibility[self.new]["version"] = str(float(fake_version) + 0.1)

    def _grpc_cri(self, services: dict) -> dict:
        return services['cri']['containerdConfig']['plugins."io.containerd.grpc.v1.cri"']

    def test_enrich_and_finalize_inventory(self):
        self._grpc_cri(self.inventory['services'])['sandbox_image'] = 'pause-redefined'
        self._grpc_cri(self.upgrade[self.new])['sandbox_image'] = 'pause-new'

        cluster = self.new_cluster()
        sandbox_image = self._grpc_cri(cluster.inventory['services'])['sandbox_image']
        self.assertEqual('pause-new', sandbox_image, "containerdConfig is enriched incorrectly")

        finalized_inventory = utils.make_finalized_inventory(cluster)
        sandbox_image = self._grpc_cri(finalized_inventory['services'])['sandbox_image']
        self.assertEqual('pause-new', sandbox_image, "containerdConfig is enriched incorrectly")

        final_inventory = cluster.formatted_inventory
        sandbox_image = self._grpc_cri(final_inventory['services'])['sandbox_image']
        self.assertEqual('pause-new', sandbox_image, "containerdConfig is enriched incorrectly")

    def test_require_sandbox_image_redefinition(self):
        self._grpc_cri(self.inventory['services'])['sandbox_image'] = 'pause-redefined'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0013", previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('1.2', equal=True)
            self.new_cluster()

    def test_require_sandbox_image_redefinition_version_templates(self):
        before, through1, through2, after = 'v1.26.3', 'v1.26.11', 'v1.27.13', 'v1.28.9'
        for template in (False, True):
            with self.subTest(f"template: {template}"), \
                    utils.assert_raises_kme(
                        self, "KME0013", escape=True,
                        previous_version_spec=f' for version {through2}',
                        next_version_spec=f' for version {after}'):
                target_version = after if not template else '{{ values.after }}'
                self.setUpVersions('{{ values.before }}',
                                   ['{{ values.through1 }}', '{{ values.through2 }}', target_version])
                self.inventory['values'] = {
                    'before': before, 'through1': through1, 'through2': through2,
                }
                if template:
                    self.inventory['values']['after'] = after
                self._grpc_cri(self.inventory['services'])['sandbox_image'] = 'pause-redefined'
                self._grpc_cri(self.upgrade['{{ values.through1 }}'])['sandbox_image'] = 'pause-upgrade1'
                self._grpc_cri(self.upgrade['{{ values.through2 }}'])['sandbox_image'] = 'pause-upgrade2'

                self.run_actions()

    def test_require_sandbox_image_redefinition_first_step(self):
        self.setUpVersions('v1.26.3', ['v1.26.11', 'v1.27.13'])
        self._grpc_cri(self.inventory['services'])['sandbox_image'] = 'pause-redefined'
        self._grpc_cri(self.upgrade[self.upgrade_plan[0]])['sandbox_image'] = 'pause-upgrade1'

        with utils.assert_raises_kme(
                self, "KME0013", escape=True,
                previous_version_spec=f' for version {self.upgrade_plan[0]}',
                next_version_spec=f' for version {self.upgrade_plan[1]}'):
            flow.run_actions(self.new_resources(), [upgrade.UpgradeAction(self.upgrade_plan[0], 0)])

    def test_containerd_config_simple_upgrade_required(self):
        for compatibility_changed in (False, True):
            with self.subTest(f"compatibility changed: {compatibility_changed}"), \
                    utils.backup_globals():
                self._patch_globals('1.2', equal=not compatibility_changed)
                self.setUp()

                cluster = self.new_cluster()
                self.assertEqual(compatibility_changed,
                                 cluster.context["upgrade"]["required"]['containerdConfig'],
                                 "Containerd config was not scheduled for upgrade")

    def test_procedure_inventory_upgrade_required_inventory_default(self):
        for procedure_version, expected_upgrade_required in (
                ('1.2', False),
                ('1.3', True),
                ('1.4', True),
        ):
            with self.subTest(f"upgrade to {procedure_version}: {expected_upgrade_required}"), \
                    utils.backup_globals():
                self._patch_globals('1.2', equal=False)

                self.setUp()
                self._grpc_cri(self.upgrade[self.new])['sandbox_image'] = f'registry.k8s.io/pause:{procedure_version}'

                cluster = self.new_cluster()
                self.assertEqual(expected_upgrade_required,
                                 cluster.context["upgrade"]["required"]['containerdConfig'],
                                 f"Containerd config was {'not' if expected_upgrade_required else 'unexpectedly'} "
                                 f"scheduled for upgrade")

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for procedure_pause, expected_upgrade_required in (
                ('pause-inventory', False),
                ('pause-redefined', True)
        ):
            with self.subTest(f"upgrade: {expected_upgrade_required}"), utils.backup_globals():
                self._patch_globals('1.2', equal=True)

                self.setUp()
                self._grpc_cri(self.inventory['services'])['sandbox_image'] = 'pause-inventory'
                self._grpc_cri(self.upgrade[self.new])['sandbox_image'] = procedure_pause

                cluster = self.new_cluster()
                self.assertEqual(expected_upgrade_required,
                                 cluster.context["upgrade"]["required"]['containerdConfig'],
                                 f"Containerd config was {'not' if expected_upgrade_required else 'unexpectedly'} "
                                 f"scheduled for upgrade")


class InventoryRecreation(_AbstractUpgradeEnrichmentTest):
    def setUp(self):
        self.setUpVersions('v1.28.0', ['v1.28.9', 'v1.29.4', 'v1.30.1'])

    def package_names(self, services: dict, package: str, package_names) -> None:
        services.setdefault('packages', {}).setdefault('associations', {}) \
            .setdefault(package, {})['package_name'] = package_names

    def sandbox_image(self, services: dict, sandbox_image: str) -> None:
        services.setdefault('cri', {}).setdefault('containerdConfig', {})\
            .setdefault('plugins."io.containerd.grpc.v1.cri"', {})['sandbox_image'] = sandbox_image

    def test_plugins_iterative_image_redefinition(self):
        self.upgrade[self.upgrade_plan[1]].setdefault('plugins', {})\
            .setdefault('calico', {}).setdefault('cni', {})['image'] = 'A'
        self.upgrade[self.upgrade_plan[2]].setdefault('plugins', {})\
            .setdefault('calico', {}).setdefault('cni', {})['image'] = 'B'

        resources = self.run_actions()

        actual_image = resources.inventory()['plugins']['calico']['cni']['image']
        self.assertEqual('B', actual_image,
                         "Plugin image was not redefined in recreated inventory.")

    def test_plugins_iterative_custom_property_redefinition_target_unspecified(self):
        self.upgrade[self.upgrade_plan[0]].setdefault('plugins', {}).setdefault('custom-plugin', {})['property'] = 'A'
        self.upgrade[self.upgrade_plan[1]].setdefault('plugins', {}).setdefault('custom-plugin', {})['property'] = 'B'

        resources = self.run_actions()

        final_property = resources.inventory().get('plugins', {}).get('custom-plugin', {}).get('property')
        self.assertEqual('B', final_property,
                         "Custom property was not redefined in recreated inventory.")

    def test_packages_iterative_package_names_redefinition(self):
        self.package_names(self.upgrade[self.upgrade_plan[1]], 'containerd', 'A')
        self.package_names(self.upgrade[self.upgrade_plan[2]], 'containerd', 'B')

        resources = self.run_actions()

        actual_package = resources.inventory()['services']['packages']['associations']['containerd']['package_name']
        self.assertEqual('B', actual_package,
                         "Containerd packages associations were not redefined in recreated inventory.")

    def test_thirdparties_iterative_source_redefinition(self):
        self.upgrade[self.upgrade_plan[1]].setdefault('thirdparties', {})['/usr/bin/calicoctl'] = 'A'
        self.upgrade[self.upgrade_plan[2]].setdefault('thirdparties', {})['/usr/bin/calicoctl'] = {
            'source': 'B',
            'sha1': 'fake-sha1'
        }

        resources = self.run_actions()

        actual_thirdparty = resources.inventory()['services']['thirdparties']['/usr/bin/calicoctl']
        self.assertEqual('B', actual_thirdparty['source'],
                         "Source of /usr/bin/calicoctl was not redefined in recreated inventory.")
        self.assertEqual('fake-sha1', actual_thirdparty['sha1'],
                         "sha1 of /usr/bin/calicoctl was not redefined in recreated inventory.")

    def test_iterative_sandbox_image_redefinition(self):
        self.sandbox_image(self.upgrade[self.upgrade_plan[1]], 'A')
        self.sandbox_image(self.upgrade[self.upgrade_plan[2]], 'B')

        resources = self.run_actions()

        actual_image = resources.inventory()['services']['cri']['containerdConfig']\
            ['plugins."io.containerd.grpc.v1.cri"']['sandbox_image']
        self.assertEqual('B', actual_image,
                         "Containerd config was not redefined in recreated inventory.")


class RunTasks(_AbstractUpgradeEnrichmentTest):
    def _run_tasks(self, tasks_filter: str) -> demo.FakeResources:
        # pylint: disable-next=attribute-defined-outside-init
        self.context = demo.create_silent_context(['fake_path.yaml', '--tasks', tasks_filter], procedure='upgrade')

        kubernetes_nodes = [node['name'] for node in self._get_nodes({'worker', 'control-plane'})]
        with utils.mock_call(kubernetes.autodetect_non_upgraded_nodes, return_value=kubernetes_nodes):
            return self.run_actions()

    def _run_kubernetes_task(self) -> demo.FakeResources:
        with utils.mock_call(kubernetes.upgrade_first_control_plane), \
                utils.mock_call(install.deploy_coredns), \
                utils.mock_call(components.patch_kubelet_configmap), \
                utils.mock_call(kubernetes.upgrade_other_control_planes), \
                utils.mock_call(kubernetes.upgrade_workers), \
                utils.mock_call(upgrade.kubernetes_cleanup_nodes_versions):
            return self._run_tasks('kubernetes')

    def _stub_load_configmap(self, configmap: str, data: dict) -> None:
        first_control_plane = self._first_control_plane()['address']
        results = demo.create_hosts_result([first_control_plane], stdout=json.dumps(data))
        cmd = f'kubectl get configmap -n kube-system {configmap} -o json'
        self.fake_shell.add(results, 'sudo', [cmd])

    def _get_nodes(self, roles: Set[str]) -> List[dict]:
        return [node for node in self.inventory['nodes'] if set(node['roles']) & roles]

    def _first_control_plane(self) -> dict:
        return self._get_nodes({'control-plane'})[0]

    def test_kubernetes_preconfigure_apiserver_feature_gates_if_necessary(self):
        for old, new, expected_called in (
                ('v1.26.11', 'v1.27.13', False),
                ('v1.27.13', 'v1.28.9', True),
                ('v1.28.3', 'v1.28.9', False),
        ):
            with self.subTest(f"old: {old}, new: {new}"), \
                    utils.mock_call(kubernetes.components.reconfigure_components) as run:
                self.setUpVersions(old, [new])

                res = self._run_kubernetes_task()

                actual_called = run.called and 'kube-apiserver' in run.call_args[1]['components']

                self.assertEqual(expected_called, actual_called,
                                 f"kube-apiserver was {'not' if expected_called else 'unexpectedly'} preconfigured")

                apiserver_extra_args = res.working_inventory['services']['kubeadm']['apiServer']['extraArgs']
                feature_gates_expected = 'PodSecurity=true' if kutils.version_key(new)[:2] < (1, 28) else None
                self.assertEqual(feature_gates_expected, apiserver_extra_args.get('feature-gates'),
                                 "Unexpected apiserver extra args")

    def test_kubernetes_preconfigure_apiserver_feature_gates_edit_func(self):
        # pylint: disable=protected-access

        for custom_feature_gates in ('ServiceAccountIssuerDiscovery=true', None):
            with self.subTest(f"custom feature-gates: {bool(custom_feature_gates)}"), \
                    utils.mock_call(kubernetes.components._prepare_nodes_to_reconfigure_components), \
                    utils.mock_call(kubernetes.components._reconfigure_control_plane_components), \
                    utils.mock_call(kubernetes.components._update_configmap, return_value=True):
                self.setUpVersions('v1.27.13', ['v1.28.9'])

                initial_feature_gates = 'PodSecurity=true'
                if custom_feature_gates:
                    self.inventory['services']['kubeadm'].update(
                        {'apiServer': {'extraArgs': {'feature-gates': custom_feature_gates}}})
                    initial_feature_gates = custom_feature_gates + ',' + initial_feature_gates

                self._stub_load_configmap('kubeadm-config', {'data': {'ClusterConfiguration': yaml.dump({
                    'kind': 'ClusterConfiguration',
                    'kubernetesVersion': self.old,
                    'apiServer': {'extraArgs': {'feature-gates': initial_feature_gates}}
                })}})
                self._run_kubernetes_task()

                upload_config = self.fake_fs.read(self._first_control_plane()['address'], '/etc/kubernetes/upload-config.yaml')
                cluster_config = next(filter(lambda cfg: cfg['kind'] == 'ClusterConfiguration',
                                             yaml.safe_load_all(upload_config)))

                actual_extra_args = cluster_config['apiServer']['extraArgs']
                self.assertEqual(custom_feature_gates, actual_extra_args.get('feature-gates'),
                                 "Unexpected preconfigured kube-apiserver feature gates")

                self.assertEqual(self.old, cluster_config['kubernetesVersion'],
                                 "Kubernetes version should not change during preconfiguring of kube-apiserver")

    def test_kubernetes_preconfigure_kube_proxy_conntrack_min_if_necessary(self):
        for old, new, expected_called in (
                ('v1.27.13', 'v1.28.9', False),
                ('v1.28.4', 'v1.29.4', True),
        ):
            with self.subTest(f"old: {old}, new: {new}"), \
                    utils.mock_call(kubernetes.components.reconfigure_components) as run:
                self.setUpVersions(old, [new])

                res = self._run_kubernetes_task()

                actual_called = run.called and 'kube-proxy' in run.call_args[1]['components']

                self.assertEqual(expected_called, actual_called,
                                 f"kube-proxy was {'not' if expected_called else 'unexpectedly'} preconfigured")

                conntrack_min_actual = res.working_inventory['services']['kubeadm_kube-proxy'].get('conntrack', {}).get('min')
                conntrack_min_expected = None if kutils.version_key(new)[:2] < (1, 29) else 1000000
                self.assertEqual(conntrack_min_expected, conntrack_min_actual,
                                 "Unexpected kubeadm_kube-proxy.conntrack.min")

    def test_kubernetes_preconfigure_kube_proxy_conntrack_min_edit_func(self):
        # pylint: disable=protected-access

        with utils.mock_call(kubernetes.components._prepare_nodes_to_reconfigure_components), \
                utils.mock_call(kubernetes.components._reconfigure_node_components), \
                utils.mock_call(kubernetes.components._update_configmap, return_value=True), \
                utils.mock_call(kubernetes.components._kube_proxy_configmap_uploader) as kube_proxy_uploader:
            self.setUpVersions('v1.28.4', ['v1.29.4'])

            self._stub_load_configmap('kube-proxy', {'data': {'config.conf': yaml.dump({
                'kind': 'KubeProxyConfiguration',
                'conntrack': {'min': None}
            })}})
            self._run_kubernetes_task()

            self.assertTrue(kube_proxy_uploader.called, "kube-proxy ConfigMap was not updated")

            kubeadm_config: kubernetes.components.KubeadmConfig = kube_proxy_uploader.call_args[0][1]

            self.assertTrue(kubeadm_config.is_loaded('kube-proxy'), "kube-proxy ConfigMap should already be loaded")

            conntrack_min_actual = kubeadm_config.maps['kube-proxy'].get('conntrack', {}).get('min')
            self.assertEqual(1000000, conntrack_min_actual,
                             "Unexpected preconfigured kube-proxy conntrack.min")

            conntrack_min_actual = yaml.safe_load(kubeadm_config.loaded_maps['kube-proxy'].obj['data']['config.conf'])\
                .get('conntrack', {}).get('min')
            self.assertEqual(1000000, conntrack_min_actual,
                             "Unexpected preconfigured kube-proxy conntrack.min")


if __name__ == '__main__':
    unittest.main()
