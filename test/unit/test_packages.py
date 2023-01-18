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
from typing import Optional

from kubemarine import demo, packages
from kubemarine.core import static, defaults, log, errors
from kubemarine.core.yaml_merger import default_merger
from kubemarine.demo import FakeKubernetesCluster
from kubemarine.procedures import add_node
from test.unit import utils


def new_debian_cluster(inventory: dict) -> FakeKubernetesCluster:
    context = demo.create_silent_context()
    context['nodes'] = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='20.04')
    return demo.new_cluster(inventory, context=context)


def prepare_compiled_associations_defaults() -> dict:
    defs = deepcopy(static.DEFAULTS)
    defs['cluster_name'] = 'k8s.fake.local'
    context = demo.create_silent_context()
    logger = log.init_log_from_context_args(static.GLOBALS, context, defs).logger

    root = deepcopy(defs)
    root['globals'] = static.GLOBALS
    compiled_defaults = defaults.compile_object(logger, defs['services']['packages']['associations'], root)

    for association_name in packages.get_associations_os_family_keys():
        os_associations: dict = deepcopy(static.GLOBALS['packages']['common_associations'])
        if association_name == 'debian':
            del os_associations['semanage']
        for association_params in os_associations.values():
            del association_params['groups']
        default_merger.merge(os_associations, compiled_defaults[association_name])
        compiled_defaults[association_name] = os_associations

    return compiled_defaults


COMPILED_ASSOCIATIONS_DEFAULTS = prepare_compiled_associations_defaults()


def get_compiled_defaults():
    return deepcopy(COMPILED_ASSOCIATIONS_DEFAULTS)


def global_associations(inventory: dict) -> dict:
    return inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('associations', {})


def os_family_associations(inventory: dict, os_family: str) -> dict:
    return global_associations(inventory).setdefault(os_family, {})


def package_associations(inventory: dict, os_family: Optional[str], package: str) -> dict:
    return (os_family_associations(inventory, os_family) if os_family else global_associations(inventory))\
        .setdefault(package, {})


def set_cache_versions_false(inventory: dict, os_family: Optional[str], package: Optional[str]):
    section = inventory.setdefault('services', {}).setdefault('packages', {})
    if os_family or package:
        section = section.setdefault('associations', {})
    if os_family:
        section = section.setdefault(os_family, {})
    if package:
        section = section.setdefault(package, {})
    section['cache_versions'] = False


def get_package_name(os_family, package) -> str:
    return packages.get_package_name(os_family, package)


def cache_installed_packages(cluster: FakeKubernetesCluster):
    add_node.cache_installed_packages(cluster)


class PackagesEnrichment(unittest.TestCase):
    def setUp(self):
        self.inventory = demo.generate_inventory(**demo.ALLINONE)
        self.inventory['services']['packages'] = {}

    def _new_cluster(self):
        return demo.new_cluster(self.inventory)

    def _packages(self, _type=None, __type=None):
        packages = self.inventory['services']['packages']
        if _type is None:
            return packages
        if __type is None:
            return packages.setdefault(_type, [])
        return packages.setdefault(_type, {}).setdefault(__type, [])

    def test_invalid_include_type(self):
        self._packages().setdefault('install', {})['include'] = 'curl'
        with self.assertRaisesRegex(errors.FailException, r"Actual instance type is 'string'. Expected: 'array'"):
            self._new_cluster()

    def test_move_list_to_include(self):
        for type_ in ('install', 'upgrade', 'remove'):
            self._packages(type_).append('curl')
        cluster = self._new_cluster()
        packages_section = cluster.inventory['services']['packages']
        for type_ in ('install', 'upgrade', 'remove'):
            self.assertEqual(['curl'], packages_section[type_]['include'])

    def test_allow_empty_action_list(self):
        for type_ in ('install', 'upgrade', 'remove'):
            self._packages(type_)
        cluster = self._new_cluster()
        packages_section = cluster.inventory['services']['packages']
        for type_ in ('install', 'upgrade', 'remove'):
            self.assertEqual([], packages_section[type_]['include'])

    def test_missed_install_include(self):
        self._packages('install', 'exclude').append('curl')
        with self.assertRaisesRegex(errors.FailException, r"'include' is a required property"):
            self._new_cluster()

    def test_allowed_empty_upgrade_remove_include(self):
        for type_ in ('upgrade', 'remove'):
            self._packages(type_, 'exclude').append('curl')
        cluster = self._new_cluster()
        packages_section = cluster.inventory['services']['packages']
        for type_ in ('upgrade', 'remove'):
            self.assertEqual(['*'], packages_section[type_]['include'])


class AssociationsEnrichment(unittest.TestCase):
    def test_simple_enrich_defaults(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        cluster = new_debian_cluster(inventory)
        associations = global_associations(cluster.inventory)
        self.assertEqual(packages.get_associations_os_family_keys(), associations.keys(),
                         "Associations should have only OS family specific sections")
        self.assertEqual(get_compiled_defaults(), associations,
                         "Enriched associations of the cluster does not equal to enriched defaults")

    def test_redefine_os_specific_section(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        expected_pkgs = 'docker-ce'
        package_associations(inventory, 'debian', 'docker')['package_name'] = expected_pkgs
        cluster = new_debian_cluster(inventory)
        associations = global_associations(cluster.inventory)

        defs = get_compiled_defaults()
        self.assertNotEqual(expected_pkgs, defs['debian']['docker']['package_name'])
        defs['debian']['docker']['package_name'] = expected_pkgs
        self.assertEqual(defs, associations,
                         "Debian associations section was not enriched")

    def test_propagate_global_section_to_os_specific(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        expected_pkgs_1 = 'docker-ce'
        expected_pkgs_2 = ['podman', 'containerd=1.5.*']
        package_associations(inventory, None, 'docker')['package_name'] = expected_pkgs_1
        package_associations(inventory, None, 'containerd')['package_name'] = expected_pkgs_2
        cluster = new_debian_cluster(inventory)
        associations = global_associations(cluster.inventory)
        self.assertEqual(packages.get_associations_os_family_keys(), associations.keys(),
                         "Associations should have only OS family specific sections")

        defs = get_compiled_defaults()
        self.assertNotEqual(expected_pkgs_1, defs['debian']['docker']['package_name'])
        self.assertNotEqual(expected_pkgs_2, defs['debian']['containerd']['package_name'])
        defs['debian']['docker']['package_name'] = expected_pkgs_1
        defs['debian']['containerd']['package_name'] = expected_pkgs_2
        self.assertEqual(defs, associations,
                         "Debian associations section was not enriched")

    def test_error_if_global_section_redefined_for_multiple_os(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        expected_pkgs = 'docker-ce'
        package_associations(inventory, None, 'docker')['package_name'] = expected_pkgs
        context = demo.create_silent_context()
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        with self.assertRaisesRegex(Exception, packages.ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS):
            demo.new_cluster(inventory, context=context)

    def test_error_if_global_section_redefined_for_add_node_different_os(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        expected_pkgs = 'docker-ce'
        package_associations(inventory, None, 'docker')['package_name'] = expected_pkgs
        context = demo.create_silent_context(procedure='add_node')
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        add_node = {'nodes': [inventory['nodes'].pop(0)]}
        with self.assertRaisesRegex(Exception, packages.ERROR_GLOBAL_ASSOCIATIONS_REDEFINED_MULTIPLE_OS):
            demo.new_cluster(inventory, procedure_inventory=add_node, context=context)

    def test_success_if_os_specific_section_redefined_for_add_node_different_os(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        expected_pkgs = 'docker-ce'
        package_associations(inventory, 'rhel', 'docker')['package_name'] = expected_pkgs
        context = demo.create_silent_context(procedure='add_node')
        host_different_os = inventory['nodes'][0]['address']
        context['nodes'] = self._nodes_context_one_different_os(inventory, host_different_os)
        add_node = {'nodes': [inventory['nodes'].pop(0)]}
        # no error
        demo.new_cluster(inventory, procedure_inventory=add_node, context=context)

    def test_cache_versions_false_use_recommended_versions(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        set_cache_versions_false(inventory, None, None)
        cluster = new_debian_cluster(inventory)
        associations = global_associations(cluster.inventory)
        self.assertEqual(get_compiled_defaults(), associations,
                         "Even if cache_versions == false, we still need to use recommended versions")

    def test_remove_unused_os_family_associations(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        cluster = new_debian_cluster(inventory)
        finalized_inventory = packages.remove_unused_os_family_associations(cluster, cluster.inventory)
        self.assertEqual({'debian'}, global_associations(finalized_inventory).keys())

    def _nodes_context_one_different_os(self, inventory, host_different_os):
        nodes_context = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='20.04')
        nodes_context[host_different_os]['os'] = {
            'name': 'centos',
            'family': 'rhel',
            'version': '7.9'
        }
        return nodes_context


class PackagesUtilities(unittest.TestCase):
    def test_get_package_name_rhel(self):
        self.assertEqual('docker-ce', get_package_name('rhel', 'docker-ce-19.03.15-3.el7.x86_64'))
        self.assertEqual('docker-ce', get_package_name('rhel', 'docker-ce-19.03*'))
        self.assertEqual('docker-ce', get_package_name('rhel', 'docker-ce-*'))
        self.assertEqual('docker-ce', get_package_name('rhel', 'docker-ce'))

    def test_get_package_name_debian(self):
        self.assertEqual('containerd', get_package_name('debian', 'containerd=1.5.9-0ubuntu1~20.04.4'))
        self.assertEqual('containerd', get_package_name('debian', 'containerd=1.5.*'))
        self.assertEqual('containerd', get_package_name('debian', 'containerd=*'))
        self.assertEqual('containerd', get_package_name('debian', 'containerd'))

    def test_detect_versions_debian(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context()
        context['nodes'] = demo.generate_nodes_context(inventory, os_name='ubuntu', os_version='20.04')
        cluster = demo.new_cluster(inventory, context=context)

        expected_pkg = 'containerd=1.5.9-0ubuntu1~20.04.4'
        queried_pkg = 'containerd=1.5.*'
        group = cluster.nodes['all']
        results = demo.create_nodegroup_result(group, stdout=expected_pkg)
        cluster.fake_shell.add(results, 'sudo', [packages.get_detect_package_version_cmd('debian', 'containerd')])

        hosts_to_packages = {host: queried_pkg for host in group.get_hosts()}
        detected_packages = packages.detect_installed_packages_version_hosts(cluster, hosts_to_packages)
        self.assertEqual({queried_pkg}, detected_packages.keys(),
                         "Incorrect initially queries package")

        package_versions = detected_packages[queried_pkg]
        self.assertEqual({expected_pkg}, package_versions.keys(),
                         "Incorrect detected package versions")
        self.assertEqual(set(group.get_hosts()), set(package_versions[expected_pkg]),
                         "Incorrect set of hosts with detected package version")

    def test_detect_versions_rhel(self):
        inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        context = demo.create_silent_context()
        context['nodes'] = demo.generate_nodes_context(inventory, os_name='centos', os_version='7.9')
        cluster = demo.new_cluster(inventory, context=context)

        expected_pkg = 'docker-ce-19.03.15-3.el7.x86_64'
        queried_pkg = 'docker-ce-19.03*'
        group = cluster.nodes['all']
        results = demo.create_nodegroup_result(group, stdout=expected_pkg)
        cluster.fake_shell.add(results, 'sudo', [packages.get_detect_package_version_cmd('rhel', 'docker-ce')])

        hosts_to_packages = {host: [queried_pkg] for host in group.get_hosts()}
        detected_packages = packages.detect_installed_packages_version_hosts(cluster, hosts_to_packages)
        self.assertEqual({queried_pkg}, detected_packages.keys(),
                         "Incorrect initially queries package")

        package_versions = detected_packages[queried_pkg]
        self.assertEqual({expected_pkg}, package_versions.keys(),
                         "Incorrect detected package versions")
        self.assertEqual(set(group.get_hosts()), set(package_versions[expected_pkg]),
                         "Incorrect set of hosts with detected package version")


class CacheVersions(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        self.context = demo.create_silent_context(procedure='add_node')
        self.context['nodes'] = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        self.hosts = [node['address'] for node in self.inventory['nodes']]
        self.new_host = self.inventory['nodes'][0]['address']
        self.procedure_inventory = {'nodes': [self.inventory['nodes'].pop(0)]}
        self.initial_hosts = [node['address'] for node in self.inventory['nodes']]

    def _new_cluster(self):
        return demo.new_cluster(self.inventory, context=self.context, procedure_inventory=self.procedure_inventory)

    def _packages_install(self, inventory: dict):
        return inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('install', [])

    def _packages_include(self, inventory: dict):
        return inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('install', {})\
            .setdefault('include', [])

    def test_cache_versions_and_finalize_inventory(self):
        self._packages_install(self.inventory).extend(['curl2', 'unzip2'])
        cluster = self._new_cluster()
        utils.stub_associations_packages(cluster, {
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
        })
        utils.stub_detect_packages(cluster, {
            'curl2': {host: 'curl2=7.68.0-1ubuntu2.14' for host in self.hosts},
            'unzip2': {host: 'unzip2=6.0-25ubuntu1.1' for host in self.hosts},
        })

        cache_installed_packages(cluster)

        self.assertEqual('containerd=1.5.9-0ubuntu1~20.04.4',
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(cluster.inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl2', 'unzip2'}, set(self._packages_include(cluster.inventory)),
                         "Custom packages versions should be not detected when adding node")

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual('containerd=1.5.9-0ubuntu1~20.04.4',
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(finalized_inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl2=7.68.0-1ubuntu2.14', 'unzip2=6.0-25ubuntu1.1'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages versions should be detected in finalized inventory")

    def test_cache_versions_global_off(self):
        expected_containerd = 'containerd=1.5.9-0ubuntu1~20.04.4'
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]
        self.assertNotEqual(expected_containerd, default_containerd)

        set_cache_versions_false(self.inventory, None, None)
        cluster = self._new_cluster()
        utils.stub_associations_packages(cluster, {
            'containerd': {host: expected_containerd for host in self.initial_hosts},
        })

        cache_installed_packages(cluster)

        self.assertEqual(default_containerd,
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because caching versions is off")

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(expected_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")

    def test_cache_versions_specific_off(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]
        default_haproxy = get_compiled_defaults()['debian']['haproxy']['package_name']

        set_cache_versions_false(self.inventory, None, 'containerd')
        set_cache_versions_false(self.inventory, 'debian', 'haproxy')
        cluster = self._new_cluster()
        utils.stub_associations_packages(cluster, {
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
            'haproxy': {host: 'haproxy=2.0.29-0ubuntu1' for host in self.initial_hosts},
        })

        cache_installed_packages(cluster)

        self.assertEqual(default_containerd,
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because caching versions is off")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(cluster.inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual(default_haproxy,
                         package_associations(cluster.inventory, 'debian', 'haproxy')['package_name'],
                         "haproxy should be default because caching versions is off")

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual('containerd=1.5.9-0ubuntu1~20.04.4',
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(finalized_inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual('haproxy=2.0.29-0ubuntu1',
                         package_associations(finalized_inventory, 'debian', 'haproxy')['package_name'],
                         "haproxy was not detected")

    def test_add_node_fails_different_package_versions(self):
        cluster = self._new_cluster()
        utils.stub_associations_packages(cluster, {
            'containerd': {
                self.initial_hosts[0]: 'containerd=1.5.9-0ubuntu1~20.04.4',
                self.initial_hosts[1]: 'containerd=2',
            },
        })

        expected_error_regex = packages.ERROR_MULTIPLE_PACKAGE_VERSIONS_DETECTED.replace('%s', '.*')
        with self.assertRaisesRegex(Exception, expected_error_regex):
            cache_installed_packages(cluster)

    def test_finalize_inventory_different_package_versions(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]

        self._packages_install(self.inventory).extend(['curl2=7.*', 'unzip2=6.*'])
        cluster = self._new_cluster()

        utils.stub_associations_packages(cluster, {
            'containerd': {
                self.initial_hosts[0]: 'containerd=1.5.9-0ubuntu1~20.04.4',
                self.initial_hosts[1]: 'containerd=2',
            },
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
        })
        utils.stub_detect_packages(cluster, {
            'curl2': {
                self.initial_hosts[0]: 'curl2=7.68.0-1ubuntu2.14',
                self.initial_hosts[1]: 'curl2=2',
            },
            'unzip2': {host: 'unzip2=6.0-25ubuntu1.1' for host in self.hosts},
        })

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(default_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple versions are installed")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(finalized_inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl2=7.*', 'unzip2=6.0-25ubuntu1.1'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages versions should be partially detected in finalized inventory")

    def test_not_cache_versions_if_multiple_os_family_versions(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]

        self.context['nodes'][self.new_host]['os']['version'] = '22.04'
        self._packages_install(self.inventory).extend(['curl2=7.*'])
        cluster = self._new_cluster()

        utils.stub_associations_packages(cluster, {
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
        })
        utils.stub_detect_packages(cluster, {
            'curl2': {host: 'curl2=7.68.0-1ubuntu2.14' for host in self.hosts},
        })

        cache_installed_packages(cluster)

        self.assertEqual(default_containerd,
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple OS versions are detected")

        finalized_inventory = utils.make_finalized_inventory(cluster)
        self.assertEqual(default_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple OS versions are detected")
        self.assertEqual({'curl2=7.*'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages should be default because multiple OS versions are detected")


if __name__ == '__main__':
    unittest.main()
