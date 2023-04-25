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
from contextlib import contextmanager
from typing import Dict

from kubemarine import demo, packages
from kubemarine.core import utils, errors


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


def increment_version(version: str, minor=False):
    new_version = list(utils.version_key(version))
    if minor:
        new_version[1] += 1
    else:
        new_version[2] += 1
    return f"v{'.'.join(map(str, new_version))}"


@contextmanager
def assert_raises_kme(test: unittest.TestCase, code: str, **kwargs):
    expected = errors.KME(code, **kwargs)
    with test.assertRaisesRegex(errors.KME, str(expected)):
        try:
            yield
        except errors.FailException as e:
            raise e.reason
