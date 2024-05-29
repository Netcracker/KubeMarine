# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import contextlib
import re
import unittest
from contextlib import contextmanager
from copy import deepcopy
from typing import List, Tuple, Iterator, Type, Union, Callable, Any, Dict
from unittest import mock
from test.unit import utils as test_utils

from kubemarine import patches, demo, system
from kubemarine.core import static, utils, flow, summary, errors
from kubemarine.core.action import Action
from kubemarine.core.cluster import EnrichmentStage, KubernetesCluster
from kubemarine.core.patch import Patch, InventoryOnlyPatch, RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.core.yaml_merger import default_merger
from kubemarine.procedures import migrate_kubemarine
from kubemarine.procedures.migrate_kubemarine import (
    CriUpgradeAction, BalancerUpgradeAction, PluginUpgradeAction, ThirdpartyUpgradeAction
)

# pylint: disable=protected-access


def get_kubernetes_versions():
    k8s_versions = list(static.KUBERNETES_VERSIONS['compatibility_map'])
    return sorted(k8s_versions, key=utils.version_key)


@contextmanager
def mock_load_upgrade_config(changed_config: dict):
    with test_utils.backup_software_upgrade_config() as clean_config:
        default_merger.merge(clean_config, changed_config)
        yield


@contextmanager
def backup_patches() -> Iterator[List[Patch]]:
    original_patches = list(patches.patches)
    try:
        yield patches.patches
    finally:
        patches.patches = original_patches


def new_patch(id_: str, derive_from: Union[Type[InventoryOnlyPatch], Type[RegularPatch]],
              *,
              action: Callable[[DynamicResources], Any] = None,
              recreate_inventory: bool = False) -> Patch:
    class ThePatch(derive_from):
        def __init__(self):
            super().__init__(id_)

        @property
        def action(self) -> Action:
            return test_utils.new_action(id_, action=action, recreate_inventory=recreate_inventory)

        @property
        def description(self) -> str:
            return ""

    return ThePatch()


def get_patch_by_id(id_: str) -> Patch:
    return get_patches_by_ids([id_])[0]


def get_patches_by_ids(ids: List[str]) -> List[Patch]:
    patches_ = [p for p in migrate_kubemarine.load_patches() if p.identifier in ids]
    found_ids = [p.identifier for p in patches_]
    not_found_ids = set(ids) - set(found_ids)
    if not_found_ids:
        raise Exception(f"Failed to find patches with IDs {list(not_found_ids)}")

    return patches_


def generate_environment(kubernetes_version: str, scheme: dict = None) -> Tuple[dict, dict]:
    if scheme is None:
        scheme = demo.MINIHA_KEEPALIVED
    inventory = demo.generate_inventory(**scheme)
    inventory['services']['kubeadm'] = {
        'kubernetesVersion': kubernetes_version
    }
    context = demo.create_silent_context(['fake_path.yaml'], procedure='migrate_kubemarine')
    return inventory, context


@contextmanager
def mock_cluster_enrich_max_stage() -> Iterator[List[EnrichmentStage]]:
    cluster_enrich_orig = KubernetesCluster.enrich
    max_stage = [EnrichmentStage.NONE]

    def cluster_enrich_mocked(cluster: KubernetesCluster, *args, **kwargs):
        if args[0] > max_stage[0]:
            max_stage[0] = args[0]
        return cluster_enrich_orig(cluster, *args, **kwargs)

    with mock.patch.object(KubernetesCluster, cluster_enrich_orig.__name__, new=cluster_enrich_mocked):
        yield max_stage


class PatchesResolvingTest(unittest.TestCase):
    def test_patches_order(self):
        k8s_latest = get_kubernetes_versions()[-1]
        changed_config = {
            'plugins': {'calico': [k8s_latest], 'local-path-provisioner': [k8s_latest],
                        'kubernetes-dashboard': [k8s_latest], 'nginx-ingress-controller': [k8s_latest]},
            'thirdparties': {'crictl': [k8s_latest]},
            'packages': {'containerd': {'version_debian': [k8s_latest]},
                         'haproxy': {'version_debian': [k8s_latest]},
                         'keepalived': {'version_debian': [k8s_latest]}},
        }
        with mock_load_upgrade_config(changed_config), backup_patches() as patches_list:
            patches_list.append(new_patch("test_cluster2", RegularPatch))
            patches_list.append(new_patch("test_inventory1", InventoryOnlyPatch))
            patches_list.append(new_patch("test_inventory2", InventoryOnlyPatch))
            patches_list.append(new_patch("test_cluster1", RegularPatch))

            resolved_patches = migrate_kubemarine.load_patches()
            expected_order = ['test_inventory1', 'test_inventory2',
                              'upgrade_crictl', 'upgrade_cri', 'upgrade_haproxy', 'upgrade_keepalived',
                              'upgrade_calico', 'upgrade_nginx_ingress_controller',
                              'upgrade_kubernetes_dashboard', 'upgrade_local_path_provisioner',
                              'test_cluster2', 'test_cluster1']
            self.assertEqual(expected_order,
                             [p.identifier for p in resolved_patches if p.identifier in expected_order],
                             "Unexpected order of resolved patches")


class UpgradeCRI(unittest.TestCase):
    def prepare_environment(self, os_name: str, os_version: str):
        # pylint: disable=attribute-defined-outside-init

        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
        self.migrate_kubemarine = demo.generate_procedure_inventory('migrate_kubemarine')

        associations = {}
        for sample_package in ('containerd', 'haproxy', 'keepalived'):
            associations[sample_package] = {}

        self.migrate_kubemarine['upgrade'] = {'packages': {
            'associations': deepcopy(associations)
        }}

        for sample_package in ('audit', 'conntrack'):
            associations[sample_package] = {}

        os_family = system.detect_os_family_by_name_version(os_name, os_version)
        associations[os_family] = deepcopy(associations)

        self.inventory['services']['packages'] = {
            'associations': deepcopy(associations),
        }

        self.changed_config = {
            'packages': {
                'containerdio': {}, 'containerd': {}
            }
        }

    def test_enrich_and_finalize_inventory(self):
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] = 'containerd-new'
        res = self._run_and_check(True, EnrichmentStage.PROCEDURE)

        associations = res.working_inventory['services']['packages']['associations']['debian']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

        associations = res.finalized_inventory['services']['packages']['associations']['debian']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

        associations = res.inventory()['services']['packages']['associations']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

    def test_run_other_patch_not_enrich_inventory(self):
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] = 'containerd-new'

        self.changed_config['thirdparties'] = {'crictl': [self.kubernetes_version]}
        res = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_crictl').action
            flow.run_actions(res, [action])
            self.assertTrue(run.called, f"Other patch was not run")

        associations = res.working_inventory['services']['packages']['associations']['debian']
        self.assertNotEqual('containerd-new', associations['containerd']['package_name'],
                            "Package associations should not be enriched")

        associations = res.inventory()['services']['packages']['associations']
        self.assertNotEqual('containerd-new', associations['containerd'].get('package_name'),
                            "Package associations should not be enriched")

    def test_simple_upgrade_required(self):
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self._run_and_check(True, EnrichmentStage.PROCEDURE)

    def test_specific_os_family_cri_association_upgrade_required(self):
        for os_name, os_family, os_version in (
                ('ubuntu', 'debian', '20.04'),
                ('centos', 'rhel', '7.9'),
                ('rhel', 'rhel8', '8.7'),
                ('rhel', 'rhel9', '9.2')
        ):
            for package_vary in ('containerd', 'containerdio'):
                expected_upgrade_required = package_vary in self._packages_for_cri_os_family(os_family)

                with self.subTest(f"{os_family}, {package_vary}"):
                    self.prepare_environment(os_name, os_version)
                    self.changed_config['packages'][package_vary][f"version_{os_family}"] = [self.kubernetes_version]
                    self._run_and_check(expected_upgrade_required,
                                        EnrichmentStage.PROCEDURE if expected_upgrade_required else EnrichmentStage.DEFAULT)

    def _packages_for_cri_os_family(self, os_family: str) -> List[str]:
        if os_family in ('rhel', 'rhel8', 'rhel9'):
            package_names = ['containerdio']
        else:
            package_names = ['containerd']

        return package_names

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for global_section in (False, True):
            for procedure_associations, expected_upgrade_required in (
                    ('containerd-inventory', False),
                    ('containerd-redefined', True)
            ):
                with self.subTest(f"global: {global_section}, upgrade: {expected_upgrade_required}"):
                    self.prepare_environment('ubuntu', '20.04')
                    self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]

                    associations = self.inventory['services']['packages']['associations']
                    if not global_section:
                        associations = associations['debian']
                    associations['containerd']['package_name'] = 'containerd-inventory'
                    self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] \
                        = procedure_associations

                    self._run_and_check(expected_upgrade_required, EnrichmentStage.PROCEDURE)

    def test_package_template_upgrade_required(self):
        for template in (False, True):
            with self.subTest(f"template: {template}"):
                self.prepare_environment('ubuntu', '20.04')

                redefined_package, expected_package = 'containerd-inventory', 'containerd-inventory'
                if template:
                    redefined_package += ('={{ globals.compatibility_map.software'
                                          '.containerd[services.kubeadm.kubernetesVersion].version_debian }}')
                    expected_package += "=" + static.GLOBALS['compatibility_map']['software']\
                        ['containerd'][self.kubernetes_version]['version_debian']

                redefined_associations = ['podman', redefined_package]
                expected_associations = ['podman', expected_package]

                self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
                self.inventory['services']['packages']['associations']\
                    ['containerd']['package_name'] = redefined_associations
                self.migrate_kubemarine['upgrade']['packages']['associations']\
                    ['containerd']['package_name'] = redefined_associations
                res = self._run_and_check(template, EnrichmentStage.PROCEDURE)

                actual_package = res.working_inventory['services']['packages']['associations']['debian']\
                    ['containerd']['package_name']
                self.assertEqual(expected_associations, actual_package,
                                 "Package names were not compiled using procedure inventory")

                actual_package = res.finalized_inventory['services']['packages']['associations']['debian']\
                    ['containerd']['package_name']
                self.assertEqual(expected_associations, actual_package,
                                 "Package names were not compiled using procedure inventory")

                actual_package = res.inventory()['services']['packages']['associations']['containerd']['package_name']
                self.assertEqual(redefined_associations, actual_package,
                                 "Package names were not enriched from procedure inventory")

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [get_kubernetes_versions()[-2]]
        self._run_and_check(False, EnrichmentStage.DEFAULT)

    def test_changed_other_os_family_upgrade_not_required(self):
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_rhel'] = [self.kubernetes_version]
        self._run_and_check(False, EnrichmentStage.DEFAULT)

    def test_require_package_redefinition(self):
        for global_section in (False, True):
            with self.subTest(f"global: {global_section}"), \
                    test_utils.assert_raises_kme(self, "KME0010", package='containerd',
                                                 previous_version_spec='', next_version_spec=''):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]

                associations = self.inventory['services']['packages']['associations']
                if not global_section:
                    associations = associations['debian']
                associations['containerd']['package_name'] = 'containerd-redefined'

                self._run_and_check(False, EnrichmentStage.DEFAULT)

    def test_dont_require_package_redefinition_patch_does_not_support_upgrade(self):
        for package in ('haproxy', 'keepalived', 'audit', 'conntrack'):
            for global_section in (False, True):
                with self.subTest(f"package: {package}, global: {global_section}"):
                    self.prepare_environment('ubuntu', '20.04')
                    self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]

                    associations = self.inventory['services']['packages']['associations']
                    if not global_section:
                        associations = associations['debian']
                    associations[package]['package_name'] = f'{package}-redefined'

                    # no error
                    self._run_and_check(True, EnrichmentStage.PROCEDURE)

    def test_run_other_patch_not_require_package_redefinition(self):
        self.prepare_environment('ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-redefined'

        self.changed_config['plugins'] = {'calico': [self.kubernetes_version]}
        res = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_calico').action
            flow.run_actions(res, [action])
            self.assertTrue(run.called, f"Other patch was not run")

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, called: bool, expected_max_stage: EnrichmentStage) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(CriUpgradeAction, CriUpgradeAction._run.__name__) as run, \
                mock_cluster_enrich_max_stage() as actual_max_stage:
            action = get_patch_by_id('upgrade_cri').action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")
            self.assertEqual(expected_max_stage, actual_max_stage[0], "Cluster was enriched to unexpected state")

        return resources


class UpgradePlugins(unittest.TestCase):
    def setUp(self):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.inventory['plugins'] = {}
        self.migrate_kubemarine = demo.generate_procedure_inventory('migrate_kubemarine')
        self.migrate_kubemarine['upgrade'] = {'plugins': {}}
        self.changed_config = {'plugins': {}}

    def test_enrich_and_finalize_inventory(self):
        self.changed_config['plugins']['kubernetes-dashboard'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['kubernetes-dashboard'] \
            = {'dashboard': {'image': 'dashboard-image-new'}}

        res = self._run_and_check('upgrade_kubernetes_dashboard', True, EnrichmentStage.PROCEDURE)

        dashboard = res.working_inventory['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

        dashboard = res.finalized_inventory['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

        dashboard = res.inventory()['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

    def test_enrich_calico_calicoctl(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['calico'] \
            = {'node': {'image': 'calico-node-new'}}

        self.changed_config['thirdparties'] = {'calicoctl': [self.kubernetes_version]}
        self.migrate_kubemarine['upgrade']['thirdparties'] = {'/usr/bin/calicoctl': {'source': 'calicoctl-new'}}

        res = self._run_and_check('upgrade_calico', True, EnrichmentStage.PROCEDURE)
        calico = res.working_inventory['plugins']['calico']
        self.assertEqual('calico-node-new', calico['node']['image'],
                         "Calico image was not enriched from procedure inventory")
        crictl = res.working_inventory['services']['thirdparties']['/usr/bin/calicoctl']
        self.assertEqual('calicoctl-new', crictl['source'],
                         "Calicoctl source was not enriched from procedure inventory")

    def test_run_other_patch_not_enrich_inventory(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['calico'] \
            = {'node': {'image': 'calico-node-new'}}

        self.changed_config['plugins']['kubernetes-dashboard'] = [self.kubernetes_version]
        res = self._run_and_check('upgrade_kubernetes_dashboard', True, EnrichmentStage.PROCEDURE)

        dashboard = res.working_inventory['plugins']['calico']
        self.assertNotEqual('calico-node-new', dashboard['node']['image'],
                            "Calico image should not be enriched")

        dashboard = res.inventory()['plugins'].get('calico', {})
        self.assertNotEqual('calico-node-new', dashboard.get('node', {}).get('image'),
                            "Calico image should not be enriched")

    def test_simple_upgrade_required(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self._run_and_check('upgrade_calico', True, EnrichmentStage.PROCEDURE)

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        self.changed_config['plugins']['calico'] = [get_kubernetes_versions()[-2]]
        self._run_and_check('upgrade_calico', False, EnrichmentStage.DEFAULT)

    def test_require_image_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['plugins']['calico'] = {'node': {'image': 'calico-node-redefined'}}
        with test_utils.assert_raises_kme(self, "KME0009",
                                          key='image', plugin_name='calico',
                                          previous_version_spec='', next_version_spec=''):
            self._run_and_check('upgrade_calico', False, EnrichmentStage.PROCEDURE)

    def test_calico_require_calicoctl_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties'] = {'/usr/bin/calicoctl': {'source': 'calicoctl-redefined'}}
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='source', thirdparty='/usr/bin/calicoctl',
                                          previous_version_spec='', next_version_spec=''):
            self._run_and_check('upgrade_calico', False, EnrichmentStage.PROCEDURE)

    def test_run_other_patch_not_require_image_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['plugins']['calico'] = {'node': {'image': 'calico-node-redefined'}}

        self.changed_config['plugins'].update({'local-path-provisioner': [self.kubernetes_version]})
        self._run_and_check('upgrade_local_path_provisioner', True, EnrichmentStage.PROCEDURE)

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool, expected_max_stage: EnrichmentStage) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__) as run, \
                mock_cluster_enrich_max_stage() as actual_max_stage:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")
            self.assertEqual(expected_max_stage, actual_max_stage[0], "Cluster was enriched to unexpected state")

        return resources


class UpgradeThirdparties(unittest.TestCase):
    def setUp(self):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.inventory['services'].update({'thirdparties': {}})
        self.migrate_kubemarine = demo.generate_procedure_inventory('migrate_kubemarine')
        self.migrate_kubemarine['upgrade'] = {'thirdparties': {}}
        self.changed_config = {'thirdparties': {}}

    def test_enrich_and_finalize_inventory(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] \
            = {'source': 'crictl-new', 'sha1': 'fake-sha1'}

        res = self._run_and_check('upgrade_crictl', True, EnrichmentStage.PROCEDURE)

        crictl = res.working_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

        crictl = res.finalized_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

        crictl = res.inventory()['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

    def test_run_other_patch_not_enrich_inventory(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] \
            = {'source': 'crictl-new'}

        self.changed_config['plugins'] = {'calico': [self.kubernetes_version]}
        res = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_calico').action
            flow.run_actions(res, [action])
            self.assertTrue(run.called, f"Other patch was not run")

        crictl = res.working_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertNotEqual('crictl-new', crictl['source'],
                            "Source should not be enriched")

        crictl = res.inventory()['services']['thirdparties'].get('/usr/bin/crictl.tar.gz', {})
        self.assertNotEqual('crictl-new', crictl.get('source'),
                            "Source should not be enriched")

    def test_enrich_and_finalize_source_template(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        template = 'crictl-{{ globals.compatibility_map.software.crictl[services.kubeadm.kubernetesVersion].version }}'
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = template
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] = template

        res = self._run_and_check('upgrade_crictl', True, EnrichmentStage.PROCEDURE)

        expected_crictl_version = static.GLOBALS['compatibility_map']['software']\
            ['crictl'][self.kubernetes_version]['version']
        expected_crictl = f"crictl-{expected_crictl_version}"

        crictl = res.working_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual(expected_crictl, crictl['source'],
                         "Source was not compiled using procedure inventory")

        crictl = res.finalized_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual(expected_crictl, crictl['source'],
                         "Source was not compiled using procedure inventory")

        crictl = res.inventory()['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual(template, crictl['source'],
                         "Source was not enriched from procedure inventory")

    def test_simple_upgrade_required(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self._run_and_check('upgrade_crictl', True, EnrichmentStage.PROCEDURE)

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        self.changed_config['thirdparties']['crictl'] = [get_kubernetes_versions()[-2]]
        self._run_and_check('upgrade_crictl', False, EnrichmentStage.DEFAULT)

    def test_require_source_redefinition(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='source', thirdparty='/usr/bin/crictl.tar.gz',
                                          previous_version_spec='.*', next_version_spec='.*'):
            self._run_and_check('upgrade_crictl', False, EnrichmentStage.PROCEDURE)

    def test_require_sha1_redefinition(self):
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = {
            'source': 'crictl-redefined',
            'sha1': 'fake-sha1'
        }
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-new'
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='sha1', thirdparty='/usr/bin/crictl.tar.gz',
                                          previous_version_spec='.*', next_version_spec='.*'):
            self._run_and_check('upgrade_crictl', False, EnrichmentStage.PROCEDURE)

    def test_run_other_patch_not_require_source_redefinition(self):
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'

        self.changed_config['packages'] = {'haproxy': {'version_debian': True}}
        res = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(BalancerUpgradeAction, BalancerUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_haproxy').action
            flow.run_actions(res, [action])
            self.assertTrue(run.called, f"Other patch was not run")

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool, expected_max_stage: EnrichmentStage) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__) as run, \
                mock_cluster_enrich_max_stage() as actual_max_stage:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")
            self.assertEqual(expected_max_stage, actual_max_stage[0], "Cluster was enriched to unexpected state")

        return resources


class UpgradeBalancers(unittest.TestCase):
    def prepare_environment(self, os_name: str, os_version: str, scheme: dict = None):
        # pylint: disable=attribute-defined-outside-init

        if scheme is None:
            scheme = demo.MINIHA_KEEPALIVED

        self.inventory, self.context = generate_environment(get_kubernetes_versions()[-1], scheme=scheme)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
        self.migrate_kubemarine = demo.generate_procedure_inventory('migrate_kubemarine')

        associations = {
            'haproxy': {},
            'keepalived': {}
        }
        self.migrate_kubemarine['upgrade'] = {'packages': {
            'associations': deepcopy(associations)
        }}

        os_family = system.detect_os_family_by_name_version(os_name, os_version)
        associations[os_family] = deepcopy(associations)

        self.inventory['services']['packages'] = {
            'associations': deepcopy(associations),
        }

        self.changed_config = {
            'packages': {
                'haproxy': {},
                'keepalived': {}
            }
        }

    def test_enrich_and_finalize_inventory(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] = f'{package}-new'
                res = self._run_and_check(f'upgrade_{package}', True, EnrichmentStage.PROCEDURE)

                associations = res.working_inventory['services']['packages']['associations']['debian']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

                associations = res.finalized_inventory['services']['packages']['associations']['debian']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

                associations = res.inventory()['services']['packages']['associations']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

    def test_run_other_patch_not_enrich_inventory(self):
        for package, other_package in (('haproxy', 'keepalived'), ('keepalived', 'haproxy')):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] = f'{package}-new'

                self.changed_config['packages'][other_package]['version_debian'] = True
                res = self._run_and_check(f'upgrade_{other_package}', True, EnrichmentStage.PROCEDURE)

                associations = res.working_inventory['services']['packages']['associations']['debian']
                self.assertNotEqual(f'{package}-new', associations[package]['package_name'],
                                    "Package associations should not be enriched")

                associations = res.inventory()['services']['packages']['associations']
                self.assertNotEqual(f'{package}-new', associations[package].get('package_name'),
                                    "Package associations should not be enriched")

    def test_simple_upgrade_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self._run_and_check(f'upgrade_{package}', True, EnrichmentStage.PROCEDURE)

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for package in ('haproxy', 'keepalived'):
            for global_section in (False, True):
                for procedure_associations, expected_upgrade_required in (
                        (f'{package}-inventory', False),
                        (f'{package}-redefined', True)
                ):
                    with self.subTest(f"package: {package}, global: {global_section}, upgrade: {expected_upgrade_required}"):
                        self.prepare_environment('ubuntu', '20.04')
                        self.changed_config['packages'][package]['version_debian'] = True

                        associations = self.inventory['services']['packages']['associations']
                        if not global_section:
                            associations = associations['debian']
                        associations[package]['package_name'] = f'{package}-inventory'
                        self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] \
                            = procedure_associations

                        self._run_and_check(f'upgrade_{package}', expected_upgrade_required, EnrichmentStage.PROCEDURE)

    def test_package_template_upgrade_required(self):
        for package in ('haproxy', 'keepalived'):
            for template in (False, True):
                with self.subTest(f"package: {package}, template: {template}"):
                    self.prepare_environment('ubuntu', '20.04')

                    redefined_package, expected_package = f'{package}-inventory', f'{package}-inventory'
                    if template:
                        redefined_package += f'={{{{ globals.compatibility_map.software.{package}.version_debian }}}}'
                        expected_package += f"={static.GLOBALS['compatibility_map']['software'][package]['version_debian']}"

                    self.changed_config['packages'][package]['version_debian'] = True
                    self.inventory['services']['packages']['associations'][package]['package_name'] = redefined_package
                    self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] = redefined_package
                    res = self._run_and_check(f'upgrade_{package}', template, EnrichmentStage.PROCEDURE)

                    actual_package = res.working_inventory['services']['packages']['associations']['debian']\
                        [package]['package_name']
                    self.assertEqual(expected_package, actual_package,
                                     "Package names were not compiled using procedure inventory")

                    actual_package = res.finalized_inventory['services']['packages']['associations']['debian']\
                        [package]['package_name']
                    self.assertEqual(expected_package, actual_package,
                                     "Package names were not compiled using procedure inventory")

                    actual_package = res.inventory()['services']['packages']['associations'][package]['package_name']
                    self.assertEqual(redefined_package, actual_package,
                                     "Package names were not enriched from procedure inventory")

    def test_changed_other_os_family_upgrade_not_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_rhel'] = True
                self._run_and_check(f'upgrade_{package}', False, EnrichmentStage.DEFAULT)

    def test_no_balancers_upgrade_not_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04', scheme=demo.FULLHA_NOBALANCERS)
                self.changed_config['packages'][package]['version_debian'] = True
                self._run_and_check(f'upgrade_{package}', False, EnrichmentStage.DEFAULT)

    def test_no_keepalived_upgrade_not_required(self):
        self.prepare_environment('ubuntu', '20.04', scheme=demo.NON_HA_BALANCER)
        self.changed_config['packages']['keepalived']['version_debian'] = True
        self._run_and_check(f'upgrade_keepalived', False, EnrichmentStage.DEFAULT)

    def test_require_package_redefinition(self):
        for package in ('haproxy', 'keepalived'):
            for global_section in (False, True):
                with self.subTest(f"package: {package}, global: {global_section}"), \
                        test_utils.assert_raises_kme(self, "KME0010", package=package,
                                                     previous_version_spec='', next_version_spec=''):
                    self.prepare_environment('ubuntu', '20.04')
                    self.changed_config['packages'][package]['version_debian'] = True

                    associations = self.inventory['services']['packages']['associations']
                    if not global_section:
                        associations = associations['debian']
                    associations[package]['package_name'] = f'{package}-redefined'

                    self._run_and_check(f'upgrade_{package}', False, EnrichmentStage.PROCEDURE)

    def test_run_other_patch_not_require_package_redefinition(self):
        for package, other_package in (('haproxy', 'keepalived'), ('keepalived', 'haproxy')):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.inventory['services']['packages']['associations'][package]['package_name'] = f'{package}-redefined'

                self.changed_config['packages'][other_package]['version_debian'] = True
                self._run_and_check(f'upgrade_{other_package}', True, EnrichmentStage.PROCEDURE)

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool, expected_max_stage: EnrichmentStage) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(BalancerUpgradeAction, BalancerUpgradeAction._run.__name__) as run, \
                mock_cluster_enrich_max_stage() as actual_max_stage:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")
            self.assertEqual(expected_max_stage, actual_max_stage[0], "Cluster was enriched to unexpected state")

        return resources


class RunPatchesSequenceTest(unittest.TestCase):
    def setUp(self):
        self.prepare_environment()

    def prepare_environment(self, os_name: str = 'ubuntu', os_version: str = '22.04'):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version, scheme=demo.ALLINONE)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
        self.migrate_kubemarine = demo.generate_procedure_inventory('migrate_kubemarine')
        self.migrate_kubemarine['upgrade'] = {}

        self.changed_config = {
            'thirdparties': {},
            'packages': {
                'containerdio': {}, 'containerd': {}, 'haproxy': {}, 'keepalived': {},
            },
            'plugins': {},
        }

    def _new_resources(self) -> demo.FakeResources:
        return test_utils.FakeResources(self.context, self.inventory,
                                        procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def test_run_two_upgrade_patches(self):
        for first_result in ('skipped', 'run'):
            for second_result in ('skipped', 'run', 'failed'):
                for first, second in (
                        ('crictl', 'containerd'),
                        ('crictl', 'keepalived'),
                        ('crictl', 'nginx-ingress-controller'),
                        ('containerd', 'haproxy'),
                        ('containerd', 'calico'),
                        ('keepalived', 'calico'),
                        ('calico', 'nginx-ingress-controller'),
                ):
                    with self.subTest(f"{first}: {first_result}, {second}: {second_result}"):
                        self._test_run_upgrade_two_patches((first, first_result), (second, second_result))

    def _prepare_environment_for_service_upgrade(self, service: str, result: str):
        if service == 'crictl':
            if result in ('run', 'failed'):
                self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
            else:
                if len(get_kubernetes_versions()) == 1:
                    self.skipTest("Cannot change other Kubernetes version.")
                self.changed_config['thirdparties']['crictl'] = [get_kubernetes_versions()[-2]]

            if result == 'failed':
                self.inventory['services'].setdefault('thirdparties', {})['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'

        elif service in ('containerd', 'keepalived', 'haproxy'):
            if result in ('run', 'failed', 'skipped'):
                # For Debian, one of keys in compatibility map for CRI matches the CRI name.
                # Keys in compatibility map for haproxy and keepalived always match the service name
                sample_compatibility_key = service
                self.changed_config['packages'][sample_compatibility_key]['version_debian'] = [self.kubernetes_version]

            # Association name always matches the CRI name or haproxy / keepalived
            association_name = service
            if result in ('failed', 'skipped'):
                self.inventory['services'].setdefault('packages', {}).setdefault('associations', {}) \
                    .setdefault(association_name, {})['package_name'] = f'{service}-redefined'

            if result == 'skipped':
                self.migrate_kubemarine['upgrade'].setdefault('packages', {}).setdefault('associations', {}) \
                    .setdefault(association_name, {})['package_name'] = f'{service}-redefined'

        elif service in ('calico', 'nginx-ingress-controller'):
            if result in ('run', 'failed'):
                self.changed_config['plugins'][service] = [self.kubernetes_version]
            else:
                if len(get_kubernetes_versions()) == 1:
                    self.skipTest("Cannot change other Kubernetes version.")
                self.changed_config['plugins'][service] = [get_kubernetes_versions()[-2]]

            if result == 'failed':
                plugin_section = 'cni' if service == 'calico' else 'controller'
                self.inventory.setdefault('plugins', {}).setdefault(service, {}) \
                    .setdefault(plugin_section, {})['image'] = 'image-redefined'

    def _test_run_upgrade_two_patches(self, first: Tuple[str, str], second: Tuple[str, str]):
        self.prepare_environment('ubuntu', '22.04')

        service, result = first
        self._prepare_environment_for_service_upgrade(service, result)
        service, result = second
        self._prepare_environment_for_service_upgrade(service, result)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock_load_upgrade_config(self.changed_config))

            patch_ids = []
            services_called = []
            for service, result in (first, second):
                called = result == 'run'
                services_called.append((service, called))

                if result == 'failed':
                    stack.enter_context(self._assert_raises_kme())

                if service == 'containerd':
                    service = 'cri'

                patch_ids.append(f"upgrade_{re.sub(r'-', '_', service)}")

            self._enter_services_upgraded(stack, services_called)

            resources = self._new_resources()
            actions = [p.action for p in get_patches_by_ids(patch_ids)]
            flow.run_actions(resources, actions)

    def _enter_services_upgraded(self, stack: contextlib.ExitStack, services_called: List[Tuple[str, bool]]):
        expected_upgrade_group = {}
        for service, called in services_called:
            if service == 'crictl':
                type_ = 'thirdparty'
                mock_context = mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__)
            elif service == 'containerd':
                type_ = 'cri'
                mock_context = mock.patch.object(CriUpgradeAction, CriUpgradeAction._run.__name__)
            elif service in ('keepalived', 'haproxy'):
                type_ = 'balancer'
                mock_context = mock.patch.object(BalancerUpgradeAction, BalancerUpgradeAction._run.__name__)
            else:  # service in ('calico', 'nginx-ingress-controller'):
                type_ = 'plugin'
                mock_context = mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__)

            if type_ not in expected_upgrade_group:
                expected_upgrade_group[type_] = (mock_context, {})

            expected_upgrade_group[type_][1][service] = called

        for type_, expected_upgrade in expected_upgrade_group.items():
            ctx, services = expected_upgrade
            stack.enter_context(self._services_upgraded(type_, ctx, services))

    @contextmanager
    def _services_upgraded(self, type_: str, ctx, expected_services: Dict[str, bool]):
        if type_ != 'plugin':
            self.assertTrue(len(expected_services) == 1)
        with ctx as run:
            try:
                yield
            finally:
                if type_ == 'plugin':
                    actual_called = [plugin for call_args in run.call_args_list for plugin in call_args[0][1]]
                    for service, called in expected_services.items():
                        self.assertEqual(called, service in actual_called,
                                         f"Upgrade of {service!r} was {'not' if called else 'unexpectedly'} run")
                else:
                    # pylint: disable-next=stop-iteration-return
                    service, called = next((k, v) for k, v in expected_services.items())
                    self.assertEqual(called, run.called,
                                     f"Upgrade of {service!r} was {'not' if called else 'unexpectedly'} run")

    @contextmanager
    def _assert_raises_kme(self):
        with self.assertRaisesRegex(errors.BaseKME, "KME"), test_utils.unwrap_fail():
            yield

    def test_reinstall_dashboard_change_inventory_run_other_patch_collect_summary(self):
        for change_hostname in (False, True):
            with self.subTest(f"change hostname: {change_hostname}"), \
                    backup_patches() as patches_list, \
                    test_utils.backup_software_upgrade_config() as changed_config:

                self.setUp()
                changed_config['plugins']['kubernetes-dashboard'] = [self.kubernetes_version]

                self.inventory.setdefault('plugins', {})['kubernetes-dashboard'] = {
                    'install': True,
                    'installation': {'procedures': [
                        {'python': {
                            'module': 'plugins/kubernetes_dashboard.py',
                            'method': 'schedule_summary_report',
                        }}
                    ]}
                }

                cluster_name = 'example.com'
                self.inventory['cluster_name'] = cluster_name
                expected_subdomain = 'dashboard'
                expected_hostname = None
                if change_hostname:
                    expected_subdomain = 'dashboard-changed'
                    expected_hostname = f'{expected_subdomain}.{{{{ cluster_name }}}}'
                    self.migrate_kubemarine['upgrade'].setdefault('plugins', {})['kubernetes-dashboard'] = {
                        'hostname': expected_hostname,
                    }
                enriched_hostname = f'{expected_subdomain}.{cluster_name}'

                patches_list.append(new_patch("test_cluster1", RegularPatch, action=lambda res: res.cluster()))

                actions = [p.action for p in get_patches_by_ids(['upgrade_kubernetes_dashboard', 'test_cluster1'])]
                res = self._new_resources()
                result = flow.ActionsFlow(actions).run_flow(res)

                result_context = result.context.get('summary_report', {})
                self.assertEqual(f'https://{enriched_hostname}',
                                 result_context.get(summary.SummaryItem.DASHBOARD_URL))
                self.assertIn(summary.SummaryItem.EXECUTION_TIME, result_context)

                actual_hostname = res.inventory().get('plugins', {}).get('kubernetes-dashboard', {}).get('hostname')
                self.assertEqual(expected_hostname, actual_hostname)


if __name__ == '__main__':
    unittest.main()
