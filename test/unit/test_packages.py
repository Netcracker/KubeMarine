import unittest
from copy import deepcopy
from typing import Optional, Dict

from kubemarine import demo, packages
from kubemarine.core import static, defaults, log
from kubemarine.demo import FakeKubernetesCluster
from kubemarine.procedures import add_node


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
    return defaults.compile_object(logger, defs['services']['packages']['associations'], root)


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


def make_finalized_inventory(cluster: FakeKubernetesCluster):
    return cluster.make_finalized_inventory()


def cache_installed_packages(cluster: FakeKubernetesCluster):
    add_node.cache_installed_packages(cluster)


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

        detected_packages = packages.detect_installed_packages_version_groups(group, queried_pkg)
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

        detected_packages = packages.detect_installed_packages_version_groups(group, [queried_pkg])
        self.assertEqual({queried_pkg}, detected_packages.keys(),
                         "Incorrect initially queries package")

        package_versions = detected_packages[queried_pkg]
        self.assertEqual({expected_pkg}, package_versions.keys(),
                         "Incorrect detected package versions")
        self.assertEqual(set(group.get_hosts()), set(package_versions[expected_pkg]),
                         "Incorrect set of hosts with detected package version")


class CacheVersions(unittest.TestCase):
    def setUp(self) -> None:
        self.fake_shell = demo.FakeShell()
        self.inventory = demo.generate_inventory(**demo.MINIHA_KEEPALIVED)
        self.context = demo.create_silent_context(procedure='add_node')
        self.context['nodes'] = demo.generate_nodes_context(self.inventory, os_name='ubuntu', os_version='20.04')
        self.hosts = [node['address'] for node in self.inventory['nodes']]
        self.new_host = self.inventory['nodes'][0]['address']
        self.procedure_inventory = {'nodes': [self.inventory['nodes'].pop(0)]}
        self.initial_hosts = [node['address'] for node in self.inventory['nodes']]

    def _new_cluster(self):
        cluster = FakeKubernetesCluster(self.inventory, self.context, procedure_inventory=self.procedure_inventory,
                                        fake_shell=self.fake_shell)
        cluster.enrich()
        return cluster

    def _stub_detect_package_result(self, package, hosts_stub: Dict[str, str]):
        results = {}
        for host in self.hosts:
            if host in hosts_stub:
                results[host] = demo.create_result(stdout=hosts_stub[host])
            else:
                results[host] = demo.create_result(stdout='not installed')

        cmd = packages.get_detect_package_version_cmd('debian', package)
        self.fake_shell.add(results, 'sudo', [cmd])

    def _stub_associations_packages(self, packages_hosts_stub: Dict[str, Dict[str, str]]):
        packages_list = []
        for association_params in get_compiled_defaults()['debian'].values():
            pkgs = association_params['package_name']
            if isinstance(pkgs, str):
                pkgs = [pkgs]

            packages_list.extend(pkgs)

        packages_list = list(set(packages_list))
        for package in packages_list:
            package = get_package_name('debian', package)
            self._stub_detect_package_result(package, packages_hosts_stub.get(package, {}))

    def _packages_install(self, inventory: dict):
        return inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('install', [])

    def _packages_include(self, inventory: dict):
        return inventory.setdefault('services', {}).setdefault('packages', {}).setdefault('install', {})\
            .setdefault('include', [])

    def _stub_custom_packages(self, packages_hosts_stub: Dict[str, Dict[str, str]]):
        for package, hosts_stub in packages_hosts_stub.items():
            self._packages_install(self.inventory).append(package)
            package = get_package_name('debian', package)
            self._stub_detect_package_result(package, hosts_stub)

    def test_cache_versions_and_finalize_inventory(self):
        self._stub_associations_packages({
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
        })
        self._stub_custom_packages({
            'curl': {host: 'curl=7.68.0-1ubuntu2.14' for host in self.hosts},
            'unzip': {host: 'unzip=6.0-25ubuntu1.1' for host in self.hosts},
        })

        cluster = self._new_cluster()
        cache_installed_packages(cluster)

        self.assertEqual('containerd=1.5.9-0ubuntu1~20.04.4',
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(cluster.inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl', 'unzip'}, set(self._packages_include(cluster.inventory)),
                         "Custom packages versions should be not detected when adding node")

        finalized_inventory = make_finalized_inventory(cluster)
        self.assertEqual('containerd=1.5.9-0ubuntu1~20.04.4',
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(finalized_inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl=7.68.0-1ubuntu2.14', 'unzip=6.0-25ubuntu1.1'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages versions should be detected in finalized inventory")

    def test_cache_versions_global_off(self):
        expected_containerd = 'containerd=1.5.9-0ubuntu1~20.04.4'
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]
        self.assertNotEqual(expected_containerd, default_containerd)

        self._stub_associations_packages({
            'containerd': {host: expected_containerd for host in self.initial_hosts},
        })

        set_cache_versions_false(self.inventory, None, None)
        cluster = self._new_cluster()
        cache_installed_packages(cluster)

        self.assertEqual(default_containerd,
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because caching versions is off")

        finalized_inventory = make_finalized_inventory(cluster)
        self.assertEqual(expected_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd was not detected")

    def test_cache_versions_specific_off(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]
        default_haproxy = get_compiled_defaults()['debian']['haproxy']['package_name']

        self._stub_associations_packages({
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
            'haproxy': {host: 'haproxy=2.0.29-0ubuntu1' for host in self.initial_hosts},
        })

        set_cache_versions_false(self.inventory, None, 'containerd')
        set_cache_versions_false(self.inventory, 'debian', 'haproxy')
        cluster = self._new_cluster()
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

        finalized_inventory = make_finalized_inventory(cluster)
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
        self._stub_associations_packages({
            'containerd': {
                self.initial_hosts[0]: 'containerd=1.5.9-0ubuntu1~20.04.4',
                self.initial_hosts[1]: 'containerd=2',
            },
        })

        cluster = self._new_cluster()
        expected_error_regex = packages.ERROR_MULTIPLE_PACKAGE_VERSIONS_DETECTED.replace('%s', '.*')
        with self.assertRaisesRegex(Exception, expected_error_regex):
            cache_installed_packages(cluster)

    def test_finalize_inventory_different_package_versions(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]

        self._stub_associations_packages({
            'containerd': {
                self.initial_hosts[0]: 'containerd=1.5.9-0ubuntu1~20.04.4',
                self.initial_hosts[1]: 'containerd=2',
            },
            'auditd': {host: 'auditd=1:2.8.5-2ubuntu6' for host in self.initial_hosts},
        })
        self._stub_custom_packages({
            'curl=7.*': {
                self.initial_hosts[0]: 'curl=7.68.0-1ubuntu2.14',
                self.initial_hosts[1]: 'curl=2',
            },
            'unzip=6.*': {host: 'unzip=6.0-25ubuntu1.1' for host in self.hosts},
        })

        cluster = self._new_cluster()

        finalized_inventory = make_finalized_inventory(cluster)
        self.assertEqual(default_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple versions are installed")
        self.assertEqual('auditd=1:2.8.5-2ubuntu6',
                         package_associations(finalized_inventory, 'debian', 'audit')['package_name'],
                         "auditd was not detected")
        self.assertEqual({'curl=7.*', 'unzip=6.0-25ubuntu1.1'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages versions should be partially detected in finalized inventory")

    def test_not_cache_versions_if_multiple_os_family_versions(self):
        default_containerd = get_compiled_defaults()['debian']['containerd']['package_name'][0]

        self._stub_associations_packages({
            'containerd': {host: 'containerd=1.5.9-0ubuntu1~20.04.4' for host in self.initial_hosts},
        })
        self._stub_custom_packages({
            'curl=7.*': {host: 'curl=7.68.0-1ubuntu2.14' for host in self.hosts},
        })

        self.context['nodes'][self.new_host]['os']['version'] = '22.04'
        cluster = self._new_cluster()
        cache_installed_packages(cluster)

        self.assertEqual(default_containerd,
                         package_associations(cluster.inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple OS versions are detected")

        finalized_inventory = make_finalized_inventory(cluster)
        self.assertEqual(default_containerd,
                         package_associations(finalized_inventory, 'debian', 'containerd')['package_name'][0],
                         "containerd should be default because multiple OS versions are detected")
        self.assertEqual({'curl=7.*'}, set(self._packages_include(finalized_inventory)),
                         "Custom packages should be default because multiple OS versions are detected")
