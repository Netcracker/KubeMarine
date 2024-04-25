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
import functools
import inspect
import logging
import os
import re
import tempfile
import unittest
from contextlib import contextmanager
from copy import deepcopy
from types import FunctionType
from typing import Dict, Iterator, Callable, cast, Any, List, Optional, Union, Type
from unittest import mock

import yaml

from kubemarine import demo, packages
from kubemarine.core import utils, errors, static, resources as res, log
from kubemarine.core.action import Action
from kubemarine.procedures import migrate_kubemarine


class PackageStubResources(demo.FakeClusterResources):
    def __init__(self, context: dict,
                 *,
                 nodes_context: Dict[str, Any] = None,
                 fake_shell: demo.FakeShell = None, fake_fs: demo.FakeFS = None):
        super().__init__(context, nodes_context=nodes_context, fake_shell=fake_shell, fake_fs=fake_fs)
        context['make_finalized_inventory'] = True

    def collect_action_result(self) -> None:
        super().collect_action_result()
        cluster = self.cluster_if_initialized()
        if cluster is not None:
            stub_associations_packages(cluster, {})


class FakeResources(demo.FakeResources, PackageStubResources):
    pass


class CommonTest(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self._tmpdir: Optional[str] = None

    @contextmanager
    def temporary_directory(self, _tmpdir: str) -> Iterator[None]:
        if self._tmpdir is not None:
            self.fail("Temporary directory is already initialized")

        try:
            self._tmpdir = _tmpdir
            yield
        finally:
            self._tmpdir = None

    @property
    def tmpdir(self) -> str:
        if self._tmpdir is None:
            self.fail("Temporary directory is not initialized")

        return self._tmpdir


def temporary_directory(wrapped: Union[CommonTest, Callable[[CommonTest], None]]):
    @contextmanager
    def helper(ct: CommonTest):
        with tempfile.TemporaryDirectory() as tmpdir, ct.temporary_directory(tmpdir):
            try:
                yield ct.tmpdir
            finally:
                logger = logging.getLogger("k8s.fake.local")
                for h in logger.handlers:
                    if isinstance(h, log.FileHandlerWithHeader):
                        h.close()

    if isinstance(wrapped, CommonTest):
        return helper(wrapped)
    else:
        @functools.wraps(wrapped)
        def wrapper(ct: CommonTest):
            with helper(ct):
                return wrapped(ct)

        return wrapper


def make_finalized_inventory(cluster: demo.FakeKubernetesCluster,
                             *,
                             stub_cache_packages: bool = True) -> dict:
    if stub_cache_packages:
        stub_associations_packages(cluster, {})

    resources = cluster.resources
    return resources.make_finalized_inventory(cluster)


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
def assert_raises_kme(test: unittest.TestCase, code: str, *, escape: bool = False, **kwargs):
    if code == 'KME0006':
        exception = errors.KME0006(**kwargs)
    else:
        exception = errors.KME(code, **kwargs)

    msg_pattern = str(exception)
    if escape:
        msg_pattern = re.escape(msg_pattern)

    with assert_raises_regex(test, type(exception), msg_pattern):
        yield


@contextmanager
def assert_raises_regex(test: unittest.TestCase, expected_exception: Type[Exception], expected_regex: str):
    with test.assertRaisesRegex(expected_exception, expected_regex), unwrap_fail():
        yield


@contextmanager
def unwrap_fail():
    try:
        yield
    except errors.FailException as e:
        if e.reason is not None:
            raise e.reason

        raise


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
def mock_call(call: Callable, return_value: object = None, side_effect: object = None) -> Iterator[mock.MagicMock]:
    func = cast(FunctionType, call)
    module = inspect.getmodule(func)
    with mock.patch.object(module, func.__name__, return_value=return_value, side_effect=side_effect) as run:
        functools.update_wrapper(run, func)
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


@contextmanager
def chdir(dir_: str) -> Iterator[None]:
    orig_cwd = os.getcwd()
    os.chdir(dir_)
    try:
        yield
    finally:
        os.chdir(orig_cwd)


def new_action(id_: str, *,
               action: Callable[[res.DynamicResources], Any] = None,
               recreate_inventory: bool = False) -> Action:

    class TheAction(Action):
        def run(self, resources: res.DynamicResources) -> None:
            if action is not None:
                action(resources)

    return TheAction(id_, recreate_inventory=recreate_inventory)
