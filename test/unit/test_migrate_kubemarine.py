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

import unittest
from contextlib import contextmanager
from typing import List, ContextManager, Tuple
from unittest import mock

import yaml

from kubemarine import patches, demo
from kubemarine.core import static, utils, flow
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch, InventoryOnlyPatch, RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.core.yaml_merger import default_merger
from kubemarine.procedures import migrate_kubemarine
from kubemarine.procedures.migrate_kubemarine import (
    CriUpgradeAction, BalancerUpgradeAction, PluginUpgradeAction, ThirdpartyUpgradeAction
)
from test.unit import utils as test_utils


def get_kubernetes_versions():
    k8s_versions = list(static.KUBERNETES_VERSIONS['compatibility_map'])
    return sorted(k8s_versions, key=utils.version_key)


@contextmanager
def mock_load_upgrade_config(changed_config: dict):
    with utils.open_internal('resources/etalons/patches/software_upgrade.yaml') as stream:
       clean_config = yaml.safe_load(stream)

    def load_upgrade_config_mocked() -> dict:
        return default_merger.merge(clean_config, changed_config)

    with mock.patch.object(migrate_kubemarine, migrate_kubemarine.load_upgrade_config.__name__,
                           side_effect=load_upgrade_config_mocked):
        yield


def get_patch_by_id(id_: str) -> Patch:
    for p in migrate_kubemarine.load_patches():
        if p.identifier == id_:
            return p
    raise Exception(f"Failed to find patch with ID={id_}")


def generate_environment(kubernetes_version: str, scheme=demo.MINIHA_KEEPALIVED) -> Tuple[dict, dict]:
    inventory = demo.generate_inventory(**scheme)
    inventory['services']['kubeadm'] = {
        'kubernetesVersion': kubernetes_version
    }
    context = demo.create_silent_context(['fake_path.yaml'], procedure='migrate_kubemarine',
                                         parser=migrate_kubemarine.new_parser())
    return inventory, context


def set_cri(inventory: dict, cri: str):
    inventory.setdefault('services', {}).setdefault('cri', {})['containerRuntime'] = cri


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
        with mock_load_upgrade_config(changed_config), self._backup_patches() as patches_list:
            patches_list.append(self._new_patch("test_cluster2", inventory_only=False))
            patches_list.append(self._new_patch("test_inventory1", inventory_only=True))
            patches_list.append(self._new_patch("test_inventory2", inventory_only=True))
            patches_list.append(self._new_patch("test_cluster1", inventory_only=False))

            resolved_patches = migrate_kubemarine.load_patches()
            expected_order = ['test_inventory1', 'test_inventory2',
                              'upgrade_crictl', 'upgrade_cri', 'upgrade_haproxy', 'upgrade_keepalived',
                              'upgrade_calico', 'upgrade_nginx_ingress_controller',
                              'upgrade_kubernetes_dashboard', 'upgrade_local_path_provisioner',
                              'test_cluster2', 'test_cluster1']
            self.assertEqual(expected_order,
                             [p.identifier for p in resolved_patches if p.identifier in expected_order],
                             "Unexpected order of resolved patches")

    def _new_patch(self, id_: str, *, inventory_only: bool) -> Patch:
        derive_from = RegularPatch
        if inventory_only:
            derive_from = InventoryOnlyPatch

        class TheAction(Action):
            def run(self, res: DynamicResources) -> None:
                return

        class ThePatch(derive_from):
            def __init__(self):
                super().__init__(id_)

            @property
            def action(self) -> Action:
                return TheAction(id_)

            @property
            def description(self) -> str:
                return ""

        return ThePatch()

    @contextmanager
    def _backup_patches(self) -> ContextManager[List[Patch]]:
        original_patches = list(patches.patches)
        try:
            yield patches.patches
        finally:
            patches.patches = original_patches


class UpgradeCRI(unittest.TestCase):
    def prepare_environment(self, cri: str, os_name: str, os_version: str):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
        self.inventory['services'].update({'packages': {'associations': {
            'docker': {},
            'containerd': {},
        }}})
        set_cri(self.inventory, cri)
        self.migrate_kubemarine: dict = {
            'upgrade': {'packages': {'associations': {
                'docker': {},
                'containerd': {}
            }}}
        }
        self.changed_config = {
            'packages': {
                'docker': {}, 'containerdio': {}, 'containerd': {}
            }
        }

    def test_enrich_and_finalize_inventory(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] = 'containerd-new'
        res = self._run_and_check(True)

        cluster = res.last_cluster
        associations = cluster.inventory['services']['packages']['associations']['debian']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

        test_utils.stub_associations_packages(cluster, {})
        associations = cluster.make_finalized_inventory()['services']['packages']['associations']['debian']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

        associations = res.stored_inventory['services']['packages']['associations']
        self.assertEqual('containerd-new', associations['containerd']['package_name'],
                         "Package associations are enriched incorrectly")

    def test_run_other_patch_not_enrich_inventory(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] = 'containerd-new'

        self.changed_config['thirdparties'] = {'crictl': [self.kubernetes_version]}
        res = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_crictl').action
            flow.run_actions(res, [action])
            self.assertTrue(run.called, f"Other patch was not run")

        cluster = res.last_cluster
        associations = cluster.inventory['services']['packages']['associations']['debian']
        self.assertNotEqual('containerd-new', associations['containerd']['package_name'],
                            "Package associations should not be enriched")

        associations = res.stored_inventory['services']['packages']['associations']
        self.assertNotEqual('containerd-new', associations['containerd'].get('package_name'),
                            "Package associations should not be enriched")

    def test_simple_upgrade_required(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self._run_and_check(True)

    def test_specific_os_family_cri_association_upgrade_required(self):
        for os_name, os_family, os_version in (
                ('ubuntu', 'debian', '20.04'),
                ('centos', 'rhel', '7.9'),
                ('rhel', 'rhel8', '8.7')
        ):
            for cri in ('docker', 'containerd'):
                for package_vary in ('docker', 'containerd', 'containerdio'):
                    expected_upgrade_required = package_vary in self._packages_for_cri_os_family(cri, os_family)

                    with self.subTest(f"{os_family}, {cri}, {package_vary}"):
                        self.prepare_environment(cri, os_name, os_version)
                        self.changed_config['packages'][package_vary][f"version_{os_family}"] = [self.kubernetes_version]
                        res = self._run_and_check(expected_upgrade_required)
                        self.assertEqual(expected_upgrade_required, res.last_cluster is not None,
                                         f"Cluster was {'not' if expected_upgrade_required else 'unexpectedly'} initialized")

    def _packages_for_cri_os_family(self, cri: str, os_family: str) -> List[str]:
        if cri == 'containerd':
            if os_family in ('rhel', 'rhel8'):
                package_names = ['containerdio']
            else:
                package_names = ['containerd']
        else:
            package_names = ['docker', 'containerdio']

        return package_names

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for procedure_associations, expected_upgrade_required in (
                ('containerd-inventory', False),
                ('containerd-redefined', True)
        ):
            with self.subTest(f"upgrade: {expected_upgrade_required}"):
                self.prepare_environment('containerd', 'ubuntu', '20.04')
                self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
                self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-inventory'
                self.migrate_kubemarine['upgrade']['packages']['associations']['containerd']['package_name'] = procedure_associations
                res = self._run_and_check(expected_upgrade_required)
                self.assertIsNotNone(res.last_cluster, "Cluster was not initialized")

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [get_kubernetes_versions()[-2]]
        res = self._run_and_check(False)
        self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_changed_other_os_family_upgrade_not_required(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_rhel'] = [self.kubernetes_version]
        res = self._run_and_check(False)
        self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_changed_not_associated_package_upgrade_not_required(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['docker']['version_debian'] = [self.kubernetes_version]
        res = self._run_and_check(False)
        self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_require_package_redefinition(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
        self.changed_config['packages']['containerd']['version_debian'] = [self.kubernetes_version]
        self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-redefined'
        with test_utils.assert_raises_kme(self, "KME0010", package='containerd',
                                          previous_version_spec='', next_version_spec=''):
            self._run_and_check(False)

    def test_run_other_patch_not_require_package_redefinition(self):
        self.prepare_environment('containerd', 'ubuntu', '20.04')
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
        return demo.FakeResources(self.context, self.inventory,
                                  procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, called: bool) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(CriUpgradeAction, CriUpgradeAction._run.__name__) as run:
            action = get_patch_by_id('upgrade_cri').action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")

        return resources


class UpgradePlugins(unittest.TestCase):
    def setUp(self):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.inventory['plugins'] = {}
        self.migrate_kubemarine: dict = {
            'upgrade': {'plugins': {}}
        }
        self.changed_config = {'plugins': {}}

    def test_enrich_and_finalize_inventory(self):
        self.changed_config['plugins']['kubernetes-dashboard'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['kubernetes-dashboard'] \
            = {'dashboard': {'image': 'dashboard-image-new'}}

        res = self._run_and_check('upgrade_kubernetes_dashboard', True)

        cluster = res.last_cluster
        dashboard = cluster.inventory['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

        test_utils.stub_associations_packages(cluster, {})
        dashboard = cluster.make_finalized_inventory()['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

        dashboard = res.stored_inventory['plugins']['kubernetes-dashboard']
        self.assertEqual('dashboard-image-new', dashboard['dashboard']['image'],
                         "Image was not enriched from procedure inventory")

    def test_enrich_calico_calicoctl(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['calico'] \
            = {'node': {'image': 'calico-node-new'}}

        self.changed_config['thirdparties'] = {'calicoctl': [self.kubernetes_version]}
        self.migrate_kubemarine['upgrade']['thirdparties'] = {'/usr/bin/calicoctl': {'source': 'calicoctl-new'}}

        res = self._run_and_check('upgrade_calico', True)
        cluster = res.last_cluster
        dashboard = cluster.inventory['plugins']['calico']
        self.assertEqual('calico-node-new', dashboard['node']['image'],
                         "Calico image was not enriched from procedure inventory")
        crictl = cluster.inventory['services']['thirdparties']['/usr/bin/calicoctl']
        self.assertEqual('calicoctl-new', crictl['source'],
                         "Calicoctl source was not enriched from procedure inventory")

    def test_run_other_patch_not_enrich_inventory(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['plugins']['calico'] \
            = {'node': {'image': 'calico-node-new'}}

        self.changed_config['plugins']['kubernetes-dashboard'] = [self.kubernetes_version]
        res = self._run_and_check('upgrade_kubernetes_dashboard', True)

        cluster = res.last_cluster
        dashboard = cluster.inventory['plugins']['calico']
        self.assertNotEqual('calico-node-new', dashboard['node']['image'],
                            "Calico image should not be enriched")

        dashboard = res.stored_inventory['plugins'].get('calico', {})
        self.assertNotEqual('calico-node-new', dashboard.get('node', {}).get('image'),
                            "Calico image should not be enriched")

    def test_simple_upgrade_required(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self._run_and_check('upgrade_calico', True)

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        self.changed_config['plugins']['calico'] = [get_kubernetes_versions()[-2]]
        res = self._run_and_check('upgrade_calico', False)
        self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_require_image_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['plugins']['calico'] = {'node': {'image': 'calico-node-redefined'}}
        with test_utils.assert_raises_kme(self, "KME0009",
                                          key='image', plugin_name='calico',
                                          previous_version_spec='', next_version_spec=''):
            self._run_and_check('upgrade_calico', False)

    def test_calico_require_calicoctl_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties'] = {'/usr/bin/calicoctl': {'source': 'calicoctl-redefined'}}
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='source', thirdparty='/usr/bin/calicoctl',
                                          previous_version_spec='', next_version_spec=''):
            self._run_and_check('upgrade_calico', False)

    def test_run_other_patch_not_require_image_redefinition(self):
        self.changed_config['plugins']['calico'] = [self.kubernetes_version]
        self.inventory['plugins']['calico'] = {'node': {'image': 'calico-node-redefined'}}

        self.changed_config['plugins'].update({'local-path-provisioner': [self.kubernetes_version]})
        self._run_and_check('upgrade_local_path_provisioner', True)

    def _new_resources(self) -> demo.FakeResources:
        return demo.FakeResources(self.context, self.inventory,
                                  procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(PluginUpgradeAction, PluginUpgradeAction._run.__name__) as run:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")

        return resources


class UpgradeThirdparties(unittest.TestCase):
    def setUp(self):
        self.kubernetes_version = get_kubernetes_versions()[-1]
        self.inventory, self.context = generate_environment(self.kubernetes_version)
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.inventory['services'].update({'thirdparties': {}})
        self.migrate_kubemarine: dict = {
            'upgrade': {'thirdparties': {}}
        }
        self.changed_config = {'thirdparties': {}}

    def test_enrich_and_finalize_inventory(self):
        set_cri(self.inventory, 'containerd')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] \
            = {'source': 'crictl-new', 'sha1': 'fake-sha1'}

        res = self._run_and_check('upgrade_crictl', True)

        cluster = res.last_cluster
        crictl = cluster.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

        test_utils.stub_associations_packages(cluster, {})
        crictl = cluster.make_finalized_inventory()['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

        crictl = res.stored_inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertEqual('crictl-new', crictl['source'],
                         "Source was not enriched from procedure inventory")
        self.assertEqual('fake-sha1', crictl['sha1'],
                         "sha1 was not enriched from procedure inventory")

    def test_run_other_patch_not_enrich_inventory(self):
        set_cri(self.inventory, 'containerd')
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

        cluster = res.last_cluster
        crictl = cluster.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz']
        self.assertNotEqual('crictl-new', crictl['source'],
                            "Source should not be enriched")

        crictl = res.stored_inventory['services']['thirdparties'].get('/usr/bin/crictl.tar.gz', {})
        self.assertNotEqual('crictl-new', crictl.get('source'),
                            "Source should not be enriched")

    def test_simple_upgrade_required(self):
        set_cri(self.inventory, 'containerd')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self._run_and_check('upgrade_crictl', True)

    def test_changed_other_kubernetes_version_upgrade_not_required(self):
        if len(get_kubernetes_versions()) == 1:
            self.skipTest("Cannot change other Kubernetes version.")
        set_cri(self.inventory, 'containerd')
        self.changed_config['thirdparties']['crictl'] = [get_kubernetes_versions()[-2]]
        res = self._run_and_check('upgrade_crictl', False)
        self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_docker_cri_upgrade_crictl_not_required(self):
        set_cri(self.inventory, 'docker')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        res = self._run_and_check('upgrade_crictl', False)
        self.assertIsNotNone(res.last_cluster, "Cluster was not initialized")

    def test_require_source_redefinition(self):
        set_cri(self.inventory, 'containerd')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-redefined'
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='source', thirdparty='/usr/bin/crictl.tar.gz',
                                          previous_version_spec='.*', next_version_spec='.*'):
            self._run_and_check('upgrade_crictl', False)

    def test_require_sha1_redefinition(self):
        set_cri(self.inventory, 'containerd')
        self.changed_config['thirdparties']['crictl'] = [self.kubernetes_version]
        self.inventory['services']['thirdparties']['/usr/bin/crictl.tar.gz'] = {
            'source': 'crictl-redefined',
            'sha1': 'fake-sha1'
        }
        self.migrate_kubemarine['upgrade']['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-new'
        with test_utils.assert_raises_kme(self, "KME0011",
                                          key='sha1', thirdparty='/usr/bin/crictl.tar.gz',
                                          previous_version_spec='.*', next_version_spec='.*'):
            self._run_and_check('upgrade_crictl', False)

    def test_run_other_patch_not_require_source_redefinition(self):
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        set_cri(self.inventory, 'containerd')
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
        return demo.FakeResources(self.context, self.inventory,
                                  procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(ThirdpartyUpgradeAction, ThirdpartyUpgradeAction._run.__name__) as run:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")

        return resources


class UpgradeBalancers(unittest.TestCase):
    def prepare_environment(self, os_name: str, os_version: str, scheme=demo.MINIHA_KEEPALIVED):
        self.inventory, self.context = generate_environment(get_kubernetes_versions()[-1], scheme=scheme)
        self.nodes_context = demo.generate_nodes_context(self.inventory, os_name=os_name, os_version=os_version)
        self.inventory['services'].update({'packages': {'associations': {
            'haproxy': {},
            'keepalived': {},
        }}})
        self.migrate_kubemarine: dict = {
            'upgrade': {'packages': {'associations': {
                'haproxy': {},
                'keepalived': {}
            }}}
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
                res = self._run_and_check(f'upgrade_{package}', True)

                cluster = res.last_cluster
                associations = cluster.inventory['services']['packages']['associations']['debian']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

                test_utils.stub_associations_packages(cluster, {})
                associations = cluster.make_finalized_inventory()['services']['packages']['associations']['debian']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

                associations = res.stored_inventory['services']['packages']['associations']
                self.assertEqual(f'{package}-new', associations[package]['package_name'],
                                 "Package associations are enriched incorrectly")

    def test_run_other_patch_not_enrich_inventory(self):
        for package, other_package in (('haproxy', 'keepalived'), ('keepalived', 'haproxy')):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] = f'{package}-new'

                self.changed_config['packages'][other_package]['version_debian'] = True
                res = self._run_and_check(f'upgrade_{other_package}', True)

                cluster = res.last_cluster
                associations = cluster.inventory['services']['packages']['associations']['debian']
                self.assertNotEqual(f'{package}-new', associations[package]['package_name'],
                                    "Package associations should not be enriched")

                associations = res.stored_inventory['services']['packages']['associations']
                self.assertNotEqual(f'{package}-new', associations[package].get('package_name'),
                                    "Package associations should not be enriched")

    def test_simple_upgrade_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self._run_and_check(f'upgrade_{package}', True)

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for package in ('haproxy', 'keepalived'):
            for procedure_associations, expected_upgrade_required in (
                    (f'{package}-inventory', False),
                    (f'{package}-redefined', True)
            ):
                with self.subTest(f"upgrade: {expected_upgrade_required}"):
                    self.prepare_environment('ubuntu', '20.04')
                    self.changed_config['packages'][package]['version_debian'] = True
                    self.inventory['services']['packages']['associations'][package]['package_name'] = f'{package}-inventory'
                    self.migrate_kubemarine['upgrade']['packages']['associations'][package]['package_name'] = procedure_associations
                    res = self._run_and_check(f'upgrade_{package}', expected_upgrade_required)
                    self.assertIsNotNone(res.last_cluster, "Cluster was not initialized")

    def test_changed_other_os_family_upgrade_not_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_rhel'] = True
                res = self._run_and_check(f'upgrade_{package}', False)
                self.assertIsNone(res.last_cluster, "Enrichment should not run")

    def test_no_balancers_upgrade_not_required(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04', scheme=demo.FULLHA_NOBALANCERS)
                self.changed_config['packages'][package]['version_debian'] = True
                res = self._run_and_check(f'upgrade_{package}', False)
                self.assertIsNotNone(res.last_cluster, "Cluster was not initialized")

    def test_no_keepalived_upgrade_not_required(self):
        self.prepare_environment('ubuntu', '20.04', scheme=demo.NON_HA_BALANCER)
        self.changed_config['packages']['keepalived']['version_debian'] = True
        res = self._run_and_check(f'upgrade_keepalived', False)
        self.assertIsNotNone(res.last_cluster, "Cluster was not initialized")

    def test_require_package_redefinition(self):
        for package in ('haproxy', 'keepalived'):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.inventory['services']['packages']['associations'][package]['package_name'] = f'{package}-redefined'
                with test_utils.assert_raises_kme(self, "KME0010", package=package,
                                                  previous_version_spec='', next_version_spec=''):
                    self._run_and_check(f'upgrade_{package}', False)

    def test_run_other_patch_not_require_package_redefinition(self):
        for package, other_package in (('haproxy', 'keepalived'), ('keepalived', 'haproxy')):
            with self.subTest(package):
                self.prepare_environment('ubuntu', '20.04')
                self.changed_config['packages'][package]['version_debian'] = True
                self.inventory['services']['packages']['associations'][package]['package_name'] = f'{package}-redefined'

                self.changed_config['packages'][other_package]['version_debian'] = True
                self._run_and_check(f'upgrade_{other_package}', True)

    def _new_resources(self) -> demo.FakeResources:
        return demo.FakeResources(self.context, self.inventory,
                                  procedure_inventory=self.migrate_kubemarine, nodes_context=self.nodes_context)

    def _run_and_check(self, patch_id: str, called: bool) -> demo.FakeResources:
        resources = self._new_resources()
        with mock_load_upgrade_config(self.changed_config), \
                mock.patch.object(BalancerUpgradeAction, BalancerUpgradeAction._run.__name__) as run:
            action = get_patch_by_id(patch_id).action
            flow.run_actions(resources, [action])
            self.assertEqual(called, run.called, f"Upgrade was {'not' if called else 'unexpectedly'} run")

        return resources


if __name__ == '__main__':
    unittest.main()
