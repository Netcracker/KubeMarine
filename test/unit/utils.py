from typing import Dict

from kubemarine import demo, packages
from kubemarine.core import utils


def make_finalized_inventory(cluster: demo.FakeKubernetesCluster):
    return cluster.make_finalized_inventory()


def get_final_inventory(cluster: demo.FakeKubernetesCluster, inventory: dict):
    return utils.get_final_inventory(cluster, inventory)


def stub_detect_packages(cluster: demo.FakeKubernetesCluster, packages_hosts_stub: Dict[str, Dict[str, str]]):
    for package, hosts_stub in packages_hosts_stub.items():
        results = {}
        for host in cluster.nodes['all'].get_hosts():
            if host in hosts_stub:
                results[host] = demo.create_result(stdout=hosts_stub[host])
            else:
                results[host] = demo.create_result(stdout='not installed')

        cmd = packages.get_detect_package_version_cmd(cluster.get_os_family(), package)
        cluster.fake_shell.add(results, 'sudo', [cmd])


def stub_associations_packages(cluster: demo.FakeKubernetesCluster, packages_hosts_stub: Dict[str, Dict[str, str]]):
    packages_list = []
    for association_params in cluster.get_associations().values():
        pkgs = association_params['package_name']
        if isinstance(pkgs, str):
            pkgs = [pkgs]

        packages_list.extend(pkgs)

    packages_list = list(set(packages_list))
    for package in packages_list:
        package = packages.get_package_name(cluster.get_os_family(), package)
        packages_hosts_stub.setdefault(package, {})

    stub_detect_packages(cluster, packages_hosts_stub)
