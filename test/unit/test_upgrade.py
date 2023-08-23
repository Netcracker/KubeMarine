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
import random
import re
import unittest
from copy import deepcopy
from typing import List, Optional, Tuple

from kubemarine import kubernetes
from kubemarine.core import errors, utils as kutils, static, flow
from kubemarine.procedures import upgrade
from kubemarine import demo
from test.unit import utils


class UpgradeVerifyUpgradePlan(unittest.TestCase):

    def test_valid_upgrade_plan(self):
        upgrade.verify_upgrade_plan(self.k8s_versions()[0], self.k8s_versions()[1:])

    def test_invalid_upgrade_plan(self):
        k8s_oldest = self.k8s_versions()[0]
        k8s_latest = self.k8s_versions()[-1]
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (re.escape(k8s_oldest), re.escape(k8s_latest))):
            upgrade.verify_upgrade_plan(k8s_oldest, [k8s_latest])

    def test_upgrade_plan_not_supported_version(self):
        k8s_latest = self.k8s_versions()[-1]
        not_allowed_version = utils.increment_version(k8s_latest)
        with utils.assert_raises_kme(self, "KME0008",
                                     version=re.escape(not_allowed_version),
                                     allowed_versions='.*'):
            upgrade.verify_upgrade_plan(k8s_latest, [not_allowed_version])

    def test_incorrect_inventory_high_range(self):
        old_kubernetes_version = 'v1.23.17'
        new_kubernetes_version = 'v1.25.7'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_MINOR_RANGE_EXCEEDED
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version])

    def test_incorrect_inventory_downgrade(self):
        old_kubernetes_version = 'v1.25.7'
        new_kubernetes_version = 'v1.23.17'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_DOWNGRADE
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version])

    def test_incorrect_inventory_same_version(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.2'
        with self.assertRaisesRegex(Exception, kubernetes.ERROR_SAME
                                               % (re.escape(old_kubernetes_version), re.escape(new_kubernetes_version))):
            upgrade.verify_upgrade_plan(old_kubernetes_version, [new_kubernetes_version])

    def test_upgrade_plan_sort(self):
        k8s_oldest = self.k8s_versions()[0]
        k8s_versions = list(self.k8s_versions())[1:]
        random.shuffle(k8s_versions)
        result = upgrade.verify_upgrade_plan(k8s_oldest, k8s_versions)

        self.assertEqual(self.k8s_versions()[1:], result)

    def k8s_versions(self) -> List[str]:
        return sorted(list(static.KUBERNETES_VERSIONS['compatibility_map']), key=kutils.version_key)


def generate_upgrade_environment(old) -> Tuple[dict, dict]:
    inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
    inventory['services']['kubeadm'] = {
        'kubernetesVersion': old
    }
    context = demo.create_silent_context(['fake_path.yaml', '--without-act'], procedure='upgrade',
                                         parser=flow.new_procedure_parser("Help text"))
    return inventory, context


def set_cri(inventory: dict, cri: str):
    inventory.setdefault('services', {}).setdefault('cri', {})['containerRuntime'] = cri


class UpgradeDefaultsEnrichment(unittest.TestCase):

    def prepare_inventory(self, old, new):
        self.inventory, self.context = generate_upgrade_environment(old)
        self.context['upgrade_version'] = new
        self.upgrade: dict = {'upgrade_plan': [new]}

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, procedure_inventory=self.upgrade, context=self.context)

    def test_correct_inventory(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.11'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        cluster = self._new_cluster()
        self.assertEqual(new_kubernetes_version, cluster.inventory['services']['kubeadm']['kubernetesVersion'])

    def test_upgrade_with_default_admission(self):
        # Upgrade PSP->PSP kuber version
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.11'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        cluster = self._new_cluster()
        self.assertEqual("psp", cluster.inventory['rbac']['admission'])

        # Upgrade PSS->PSS kuber version
        old_kubernetes_version = 'v1.25.2'
        new_kubernetes_version = 'v1.25.7'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        cluster = self._new_cluster()
        self.assertEqual("pss", cluster.inventory['rbac']['admission'])

        # Upgrade PSP->PSS kuber version
        old_kubernetes_version = 'v1.24.11'
        new_kubernetes_version = 'v1.25.2'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        with self.assertRaisesRegex(Exception, "PSP is not supported in Kubernetes version higher than v1.24"):
            self._new_cluster()

    def test_incorrect_disable_eviction(self):
        old_kubernetes_version = 'v1.24.2'
        new_kubernetes_version = 'v1.24.11'
        self.prepare_inventory(old_kubernetes_version, new_kubernetes_version)
        self.upgrade['disable-eviction'] = 'true'
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'string'\. Expected: 'boolean'\."):
            self._new_cluster()


class UpgradePackagesEnrichment(unittest.TestCase):
    def setUp(self):
        self.old = 'v1.24.2'
        self.new = 'v1.24.11'
        self.inventory, self.context = generate_upgrade_environment(self.old)
        self.context['upgrade_version'] = self.new
        self.context['nodes'] = demo.generate_nodes_context(self.inventory,
                                                            os_name='ubuntu', os_version='20.04')
        self.inventory['services'].update({'packages': {'associations': {
            'docker': {},
            'containerd': {},
        }}})
        set_cri(self.inventory, 'containerd')
        self.upgrade: dict = {
            'upgrade_plan': [self.new],
            self.new: {
                'packages': {
                    'associations': {
                        'docker': {},
                        'containerd': {}
                    }
                }
            }
        }

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.upgrade),
                                context=self.context)

    def _patch_globals(self, package: str, os_family: str, *, equal=False):
        package_compatibility = static.GLOBALS['compatibility_map']['software'][package]
        package_compatibility[self.old][f"version_{os_family}"] = f'{package}-initial'
        if equal:
            package_compatibility[self.new][f"version_{os_family}"] = f'{package}-initial'
        else:
            package_compatibility[self.new][f"version_{os_family}"] = f'{package}-new'

    def test_enrich_packages_propagate_associations(self):
        set_cri(self.inventory, 'docker')
        self.upgrade[self.new]['packages']['associations']['docker']['package_name'] = 'docker-ce'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self._new_cluster()
        self.assertEqual(['curl'], cluster.inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        self.assertEqual('docker-ce', cluster.inventory['services']['packages']['associations']['debian']['docker']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_final_inventory_enrich_global(self):
        set_cri(self.inventory, 'docker')
        self.upgrade[self.new]['packages']['associations']['docker']['package_name'] = 'docker-ce'
        self.upgrade[self.new]['packages']['install'] = ['curl']
        cluster = self._new_cluster()
        final_inventory = utils.get_final_inventory(cluster, self.inventory)
        self.assertEqual(['curl'], final_inventory['services']['packages']['install']['include'],
                         "Custom packages are enriched incorrectly")
        self.assertEqual('docker-ce', final_inventory['services']['packages']['associations']['docker']['package_name'],
                         "Associations packages are enriched incorrectly")

    def test_require_package_redefinition(self):
        self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-redefined'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0010", package='containerd',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('containerd', 'debian', equal=True)
            self._new_cluster()

    def test_compatibility_upgrade_required(self):
        for os_name, os_family, os_version in (
                ('ubuntu', 'debian', '20.04'),
                ('centos', 'rhel', '7.9'),
                ('rhel', 'rhel8', '8.7')
        ):
            for cri in ('docker', 'containerd'):
                for package_vary in ('docker', 'containerd', 'containerdio'):
                    expected_upgrade_required = package_vary in self._packages_for_cri_os_family(cri, os_family)

                    with self.subTest(f"{os_family}, {cri}, {package_vary}"), utils.backup_globals():
                        self._patch_globals(package_vary, os_family, equal=False)

                        self.setUp()
                        self.context['nodes'] = demo.generate_nodes_context(self.inventory,
                                                                            os_name=os_name, os_version=os_version)
                        set_cri(self.inventory, cri)

                        cluster = self._new_cluster()
                        self.assertEqual(expected_upgrade_required,
                                         cri in cluster.context['packages']['upgrade_required'],
                                         f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

    def _packages_for_cri_os_family(self, cri: str, os_family: str) -> List[str]:
        if cri == 'containerd':
            if os_family in ('rhel', 'rhel8'):
                package_names = ['containerdio']
            else:
                package_names = ['containerd']
        else:
            package_names = ['docker', 'containerdio']

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

                cluster = self._new_cluster()
                self.assertEqual(expected_upgrade_required,
                                 'containerd' in cluster.context['packages']['upgrade_required'],
                                 f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

    def test_procedure_inventory_upgrade_required_inventory_redefined(self):
        for procedure_associations, expected_upgrade_required in (
                ('containerd-inventory', False),
                ('containerd-redefined', True)
        ):
            with self.subTest(f"upgrade: {expected_upgrade_required}"), utils.backup_globals():
                self._patch_globals('containerd', 'debian', equal=True)

                self.setUp()
                self.inventory['services']['packages']['associations']['containerd']['package_name'] = 'containerd-inventory'
                self.upgrade[self.new]['packages']['associations']['containerd']['package_name'] = procedure_associations

                cluster = self._new_cluster()
                self.assertEqual(expected_upgrade_required,
                                 'containerd' in cluster.context['packages']['upgrade_required'],
                                 f"CRI was {'not' if expected_upgrade_required else 'unexpectedly'} scheduled for upgrade")

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


class UpgradePluginsEnrichment(unittest.TestCase):
    def setUp(self):
        self.old = 'v1.24.2'
        self.new = 'v1.24.11'
        self.inventory, self.context = generate_upgrade_environment(self.old)
        self.context['upgrade_version'] = self.new
        self.inventory['plugins'] = {}
        self.upgrade: dict = {
            'upgrade_plan': [self.new],
            self.new: {
                'plugins': {}
            }
        }

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.upgrade),
                                context=self.context)

    def _patch_globals(self, plugin: str, *, equal=False):
        fake_version = 'v1.2.3'
        package_compatibility = static.GLOBALS['compatibility_map']['software'][plugin]
        package_compatibility[self.old]["version"] = fake_version
        if equal:
            package_compatibility[self.new]["version"] = fake_version
        else:
            package_compatibility[self.new]["version"] = utils.increment_version(fake_version)

    def test_redefine_image_recursive(self):
        self.inventory['plugins'].setdefault('kubernetes-dashboard', {}).setdefault('dashboard', {})['image'] = 'A'
        self.upgrade[self.new]['plugins'].setdefault('kubernetes-dashboard', {}).setdefault('dashboard', {})['image'] = 'B'

        cluster = self._new_cluster()
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
            self._new_cluster()

    def test_require_helper_pod_image_redefinition(self):
        self.inventory['plugins'].setdefault('local-path-provisioner', {})['helper-pod-image'] = 'A'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0009",
                                        key='helper-pod-image', plugin_name='local-path-provisioner',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('local-path-provisioner', equal=True)
            self._new_cluster()

    def test_require_version_redefinition(self):
        self.inventory['plugins'].setdefault('nginx-ingress-controller', {})['version'] = 'fake version'
        with utils.backup_globals(), \
                utils.assert_raises_kme(self, "KME0009",
                                        key='version', plugin_name='nginx-ingress-controller',
                                        previous_version_spec='.*', next_version_spec='.*'):
            self._patch_globals('nginx-ingress-controller', equal=True)
            self._new_cluster()


class ThirdpartiesEnrichment(unittest.TestCase):
    def setUp(self):
        self.old = 'v1.24.2'
        self.new = 'v1.24.11'
        self.inventory, self.context = generate_upgrade_environment(self.old)
        self.context['upgrade_version'] = self.new
        self.inventory['services']['thirdparties'] = {}
        self.upgrade: dict = {
            'upgrade_plan': [self.new],
            self.new: {
                'thirdparties': {}
            }
        }

    def _new_cluster(self):
        return demo.new_cluster(deepcopy(self.inventory), procedure_inventory=deepcopy(self.upgrade),
                                context=self.context)

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

        cluster = self._new_cluster()
        thirdparties_section = cluster.inventory['services']['thirdparties']

        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubeadm-new', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertEqual('fake-sha1-new', thirdparties_section['/usr/bin/kubeadm']['sha1'])
        self.assertEqual('custom1-new', thirdparties_section['/custom1']['source'])
        self.assertEqual('custom2-new', thirdparties_section['/custom2']['source'])
        self.assertEqual(['control-plane'], thirdparties_section['/custom2']['groups'])
        self.assertEqual('custom3-initial', thirdparties_section['/custom3']['source'])

        utils.stub_associations_packages(cluster, {})
        finalized_inventory = utils.make_finalized_inventory(cluster)
        thirdparties_section = finalized_inventory['services']['thirdparties']

        self.assertEqual(all_thirdparties, set(thirdparties_section.keys()))
        self.assertEqual('kubeadm-new', thirdparties_section['/usr/bin/kubeadm']['source'])
        self.assertEqual('fake-sha1-new', thirdparties_section['/usr/bin/kubeadm']['sha1'])
        self.assertEqual('custom1-new', thirdparties_section['/custom1']['source'])
        self.assertEqual('custom2-new', thirdparties_section['/custom2']['source'])
        self.assertEqual(['control-plane'], thirdparties_section['/custom2']['groups'])
        self.assertEqual('custom3-initial', thirdparties_section['/custom3']['source'])

        final_inventory = utils.get_final_inventory(cluster, self.inventory)
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
        set_cri(self.inventory, 'containerd')
        self.upgrade[self.new]['thirdparties']['/usr/bin/crictl.tar.gz'] = 'crictl-new'

        cluster = self._new_cluster()
        thirdparties_section = cluster.inventory['services']['thirdparties']
        self.assertEqual('crictl-new', thirdparties_section['/usr/bin/crictl.tar.gz']['source'])
        self.assertEqual('/usr/bin/', thirdparties_section['/usr/bin/crictl.tar.gz']['unpack'])

    def test_require_source_redefinition(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubelet'] = 'kubelet-redefined'
        self._new_cluster()
        # with utils.assert_raises_kme(self, "KME0011",
        #                              key='source', thirdparty='/usr/bin/kubelet',
        #                              previous_version_spec='.*', next_version_spec='.*'):
        #     self._new_cluster()

    def test_require_sha1_redefinition(self):
        self.inventory['services']['thirdparties']['/usr/bin/kubectl'] = {
            'source': 'kubectl-redefined',
            'sha1': 'fake-sha1'
        }
        self.upgrade[self.new]['thirdparties']['/usr/bin/kubectl'] = 'kubectl-new'

        self._new_cluster()
        # with utils.assert_raises_kme(self, "KME0011",
        #                              key='sha1', thirdparty='/usr/bin/kubectl',
        #                              previous_version_spec='.*', next_version_spec='.*'):
        #     self._new_cluster()


class InventoryRecreation(unittest.TestCase):
    def prepare_inventory(self, upgrade_plan: List[str]):
        self.old = 'v1.24.2'
        self.inventory, self.context = generate_upgrade_environment(self.old)
        self.inventory.setdefault('rbac', {})['admission'] = 'pss'
        self.nodes_context = demo.generate_nodes_context(self.inventory)
        self.upgrade: dict = {'upgrade_plan': upgrade_plan}
        self.actions = []
        for ver in upgrade_plan:
            self.upgrade[ver] = {}
            self.actions.append(upgrade.UpgradeAction(ver))

        self.resources: Optional[demo.FakeResources] = None

    def package_names(self, services: dict, package: str, package_names) -> None:
        services.setdefault('packages', {}).setdefault('associations', {}) \
            .setdefault(package, {})['package_name'] = package_names

    def run_actions(self):
        self.resources = demo.FakeResources(self.context, self.inventory,
                                            procedure_inventory=self.upgrade, nodes_context=self.nodes_context)
        flow.run_actions(self.resources, self.actions)

    def test_plugins_iterative_image_redefinition(self):
        self.prepare_inventory(['v1.24.11', 'v1.25.2', 'v1.25.7'])
        self.upgrade['v1.25.2'].setdefault('plugins', {}).setdefault('calico', {}).setdefault('cni', {})['image'] = 'A'
        self.upgrade['v1.25.7'].setdefault('plugins', {}).setdefault('calico', {}).setdefault('cni', {})['image'] = 'B'

        self.run_actions()

        actual_image = self.resources.stored_inventory['plugins']['calico']['cni']['image']
        self.assertEqual('B', actual_image,
                         "Plugin image was not redefined in recreated inventory.")

    def test_packages_iterative_package_names_redefinition(self):
        self.prepare_inventory(['v1.24.11', 'v1.25.2', 'v1.25.7'])
        set_cri(self.inventory, 'containerd')
        self.package_names(self.upgrade['v1.25.2'], 'containerd', 'A')
        self.package_names(self.upgrade['v1.25.7'], 'containerd', 'B')

        self.run_actions()

        actual_package = self.resources.stored_inventory['services']['packages']['associations']['containerd']['package_name']
        self.assertEqual('B', actual_package,
                         "Containerd packages associations were not redefined in recreated inventory.")

    def test_thirdparties_iterative_source_redefinition(self):
        self.prepare_inventory(['v1.24.11', 'v1.25.2', 'v1.25.7'])
        set_cri(self.inventory, 'containerd')
        self.upgrade['v1.25.2'].setdefault('thirdparties', {})['/usr/bin/calicoctl'] = 'A'
        self.upgrade['v1.25.7'].setdefault('thirdparties', {})['/usr/bin/calicoctl'] = {
            'source': 'B',
            'sha1': 'fake-sha1'
        }

        self.run_actions()

        actual_thirdparty = self.resources.stored_inventory['services']['thirdparties']['/usr/bin/calicoctl']
        self.assertEqual('B', actual_thirdparty['source'],
                         "Source of /usr/bin/calicoctl was not redefined in recreated inventory.")
        self.assertEqual('fake-sha1', actual_thirdparty['sha1'],
                         "sha1 of /usr/bin/calicoctl was not redefined in recreated inventory.")


if __name__ == '__main__':
    unittest.main()
