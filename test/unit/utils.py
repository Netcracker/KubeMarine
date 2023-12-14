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
import inspect
import unittest
from contextlib import contextmanager
from copy import deepcopy
from types import FunctionType
from typing import Dict, Iterator, Callable, cast, Any
from unittest import mock

from kubemarine import demo, packages
from kubemarine.core import utils, errors, static


class FakeResources(demo.FakeResources):
    def __init__(self, *args: Any, **kwargs: Any):
        kwargs['make_finalized_inventory'] = True
        super().__init__(*args, **kwargs)

    def collect_action_result(self) -> None:
        super().collect_action_result()
        cluster = self.cluster_if_initialized()
        if isinstance(cluster, demo.FakeKubernetesCluster):
            stub_associations_packages(cluster, {})


def make_finalized_inventory(cluster: demo.FakeKubernetesCluster,
                             *,
                             stub_cache_packages: bool = True) -> dict:
    if stub_cache_packages:
        stub_associations_packages(cluster, {})

    resources = cluster.resources
    resources.make_finalized_inventory = True
    resources.dump_finalized_inventory(cluster)
    return resources.finalized_inventory


def stub_detect_packages(cluster: demo.FakeKubernetesCluster, packages_hosts_stub: Dict[str, Dict[str, str]]):
    for package, hosts_stub in packages_hosts_stub.items():
        results = {}
        for host in cluster.nodes['all'].get_hosts():
            if host in hosts_stub:
                results[host] = demo.create_result(stdout=hosts_stub[host])
            else:
                results[host] = demo.create_result(stdout='not installed', code=1)

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


@contextmanager
def backup_globals():
    backup = deepcopy(static.GLOBALS)
    try:
        yield
    finally:
        static.GLOBALS = backup


@contextmanager
def mock_call(call: Callable, return_value: object = None) -> Iterator[mock.MagicMock]:
    func = cast(FunctionType, call)
    name = func.__name__
    module = inspect.getmodule(func)
    with mock.patch.object(module, name, return_value=return_value) as run:
        run.__name__ = name
        yield run
