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
import logging
import re
import unittest
from contextlib import contextmanager
from copy import deepcopy
from types import FunctionType
from typing import Dict, Iterator, Callable, cast, Any, List
from unittest import mock

import yaml

from kubemarine import demo, packages
from kubemarine.core import utils, errors, static, resources as res, log
from kubemarine.core.action import Action
from kubemarine.procedures import migrate_kubemarine


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


def prepare_dump_directory(context: dict):
    logger = logging.getLogger("k8s.fake.local")
    for h in logger.handlers:
        if isinstance(h, log.FileHandlerWithHeader):
            h.close()

    utils.prepare_dump_directory(context)


def increment_version(version: str, minor=False):
    new_version = list(utils.version_key(version))
    if minor:
        new_version[1] += 1
    else:
        new_version[2] += 1
    return f"v{'.'.join(map(str, new_version))}"


@contextmanager
def assert_raises_kme(test: unittest.TestCase, code: str, *, escape: bool = False, **kwargs):
    if code == 'KME0006':
        exception = errors.KME0006(**kwargs)
    else:
        exception = errors.KME(code, **kwargs)

    msg_pattern = str(exception)
    if escape:
        msg_pattern = re.escape(msg_pattern)
    with test.assertRaisesRegex(type(exception), msg_pattern):
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
def backup_software_upgrade_config() -> Iterator[dict]:
    with utils.open_internal('resources/etalons/patches/software_upgrade.yaml') as stream:
       clean_config = yaml.safe_load(stream)

    def load_upgrade_config_mocked() -> dict:
        return clean_config

    with mock.patch.object(migrate_kubemarine, migrate_kubemarine.load_upgrade_config.__name__,
                           side_effect=load_upgrade_config_mocked):
        yield clean_config


@contextmanager
def mock_call(call: Callable, return_value: object = None) -> Iterator[mock.MagicMock]:
    func = cast(FunctionType, call)
    name = func.__name__
    module = inspect.getmodule(func)
    with mock.patch.object(module, name, return_value=return_value) as run:
        run.__name__ = name
        yield run


@contextmanager
def mock_remote_tmp_paths(filenames: List[str]) -> Iterator[None]:
    orig = utils.get_remote_tmp_path
    i = -1

    def mocked(filename: str = None, ext: str = None) -> str:
        if filename is None:
            nonlocal i
            i += 1
            if i < len(filenames):
                filename = filenames[i]
            else:
                raise Exception(f"Requested {i + 1} temporary filename, but only {len(filenames)} are mocked")

        return orig(filename, ext)

    with mock_call(utils.get_remote_tmp_path) as run:
        run.side_effect = mocked
        yield


def new_action(id_: str, *,
               action: Callable[[res.DynamicResources], Any] = None,
               recreate_inventory: bool = False) -> Action:

    class TheAction(Action):
        def run(self, resources: res.DynamicResources) -> None:
            if action is not None:
                action(resources)

    return TheAction(id_, recreate_inventory=recreate_inventory)
