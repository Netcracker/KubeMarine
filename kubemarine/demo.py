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

from __future__ import annotations

import io
import itertools
import re
import sys
import threading
import time
from abc import ABC
from copy import deepcopy
from typing import List, Dict, Union, Any, Optional, Mapping, Iterable, IO, Tuple, cast, Callable

import fabric  # type: ignore[import-untyped]
import invoke
import yaml

from kubemarine import system, procedures
from kubemarine.core.cluster import (
    KubernetesCluster, _AnyConnectionTypes, EnrichmentStage, EnrichmentFunction, enrichment
)
from kubemarine.core import connections, static, errors, utils
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.executor import RunnersResult, GenericResult, Token, CommandTimedOut
from kubemarine.core.group import (
    AbstractGroup, NodeGroup, NodeGroupResult, DeferredGroup, RunnersGroupResult,
    GROUP_RUN_TYPE, RemoteExecutor, RunResult
)
from kubemarine.core.resources import DynamicResources

_ShellResult = Dict[str, Any]
_ROLE_SPEC = Union[int, List[str]]


class FakeShell:
    def __init__(self) -> None:
        self.results: Dict[str, List[_ShellResult]] = {}
        self.history: Dict[str, List[_ShellResult]] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        self.results = {}
        self.history = {}

    def add(self, results: Mapping[str, GenericResult], do_type: str, args: List[str], usage_limit: int = 0) -> None:
        args.sort()

        for host, result in results.items():
            result = {
                'result': result,
                'do_type': do_type,
                'args': args,
                'used_times': 0
            }

            if usage_limit > 0:
                result['usage_limit'] = usage_limit

            self.results.setdefault(host, []).append(result)

    def find(self, host: str, do_type: str, args: List[str]) -> Optional[GenericResult]:
        # TODO: Support kwargs
        with self._lock:
            results = self.results.get(host, [])
            for i, item in enumerate(results):
                if item['do_type'] == do_type and item['args'] == args:
                    history_found = any(history_item is item for history_item in self.history.get(host, []))
                    if not history_found:
                        self.history.setdefault(host, []).append(item)

                    item['used_times'] += 1
                    if item.get('usage_limit') is not None:
                        item['usage_limit'] -= 1
                        if item['usage_limit'] < 1:
                            del results[i]
                    return item['result']
            return None

    # covered by test.test_demo.TestFakeShell.test_calculate_calls
    def history_find(self, host: str, do_type: str, args: List[str]) -> List[_ShellResult]:
        # TODO: Support kwargs
        result = []
        for item in self.history.get(host, []):
            if item['do_type'] == do_type and item['args'] == args:
                result.append(item)
        return result

    def is_called_each(self, hosts: List[str], do_type: str, args: List[str]) -> bool:
        return all((self.is_called(host, do_type, args) for host in hosts))

    def is_called(self, host: str, do_type: str, args: List[str]) -> bool:
        """
        Returns true if the specified command has already been executed in FakeShell for the specified connection.
        :param host: host to check, for which the desirable command should have been executed.
        :param do_type: The type of required command
        :param args: Required command arguments
        :return: Boolean
        """
        return self.called_times(host, do_type, args) > 0

    def called_times(self, host: str, do_type: str, args: List[str]) -> int:
        """
        Returns number of times the specified command was executed in FakeShell for the specified connection.
        :param host: host to check, for which the desirable command should have been executed.
        :param do_type: The type of required command
        :param args: Required command arguments
        :return: number of calls
        """
        found_entries = self.history_find(host, do_type, args)
        total_used_times: int = sum(found_entry['used_times'] for found_entry in found_entries)
        return total_used_times


class FakeFS:
    def __init__(self) -> None:
        self.storage: Dict[str, Dict[str, str]] = {}
        self.emulate_latency = False
        self._lock = threading.Lock()

    def reset(self) -> None:
        self.storage = {}
        self.emulate_latency = False

    def reset_host(self, host: str) -> None:
        self.storage[host] = {}

    # covered by test.test_demo.TestFakeFS.test_put_file
    # covered by test.test_demo.TestFakeFS.test_put_bytesio
    # covered by test.test_group.TestGroupCall.test_write_stream
    def write(self, host: str, filename: str, data: Union[io.BytesIO, str]) -> None:
        if isinstance(data, io.BytesIO):
            # Emulate how fabric handles file-like objects.
            # See fabric.transfer.Transfer.put
            pointer = data.tell()
            try:
                data.seek(0)
                text = self._transfer(data)
            finally:
                data.seek(pointer)
        else:
            with open(data, "rb") as fl:
                text = self._transfer(fl)

        with self._lock:
            self.storage.setdefault(host, {})[filename] = text

    def _transfer(self, fl: IO) -> str:
        # Emulate how paramiko transfers files.
        # See paramiko.sftp_client.SFTPClient._transfer_with_callback
        target = io.BytesIO()
        while True:
            data = fl.read(32768)
            target.write(data)
            if self.emulate_latency:
                time.sleep(0.1)
            if len(data) == 0:
                break
        return target.getvalue().decode('utf-8')

    # covered by test.test_demo.TestFakeFS.test_put_string
    # covered by test.test_demo.TestFakeFS.test_get_nonexistent
    def read(self, host: str, filename: str) -> Optional[str]:
        return self.storage.get(host, {}).get(filename)

    # covered by test.test_demo.TestFakeFS.test_write_file_to_cluster
    def read_all(self, hosts: List[str], filename: str) -> Dict[str, Optional[str]]:
        result = {}
        for host in hosts:
            result[host] = self.read(host, filename)
        return result


class FakeClusterStorage(utils.ClusterStorage):
    def make_dir(self) -> None:
        pass

    def upload_and_rotate(self) -> None:
        cluster = cast(FakeKubernetesCluster, self.cluster)
        cluster.uploaded_archives.append(self.local_archive_path)

    def upload_info_new_control_planes(self) -> None:
        pass


class FakeKubernetesCluster(KubernetesCluster):

    def __init__(self, *args: Any, **kwargs: Any):
        self.resources: FakeClusterResources = kwargs.pop("resources")
        self.fake_shell = self.resources.fake_shell
        self.fake_fs = self.resources.fake_fs
        self.uploaded_archives: List[str] = []
        super().__init__(*args, **kwargs)

    def _create_connection_pool(self, nodes: Dict[str, dict], gateway_nodes: Dict[str, dict], hosts: List[str]) -> ConnectionPool:
        return FakeConnectionPool(nodes, gateway_nodes, hosts, self.fake_shell, self.fake_fs)

    def _create_cluster_storage(self, context: dict) -> utils.ClusterStorage:
        return FakeClusterStorage(self, context)

    def make_group(self, ips: Iterable[_AnyConnectionTypes]) -> FakeNodeGroup:
        return FakeNodeGroup(ips, self)


class FakeClusterResources(DynamicResources):
    def __init__(self, context: dict,
                 *,
                 nodes_context: Dict[str, Any] = None,
                 fake_shell: FakeShell = None, fake_fs: FakeFS = None):
        super().__init__(context)
        self.fake_shell = fake_shell if fake_shell else FakeShell()
        self.fake_fs = fake_fs if fake_fs else FakeFS()

        self.finalized_inventory: dict = {}

        self._enrichment_functions = super().enrichment_functions()
        # Let's do not assign self._nodes_context directly to make it more close to the real enrichment.
        if nodes_context is not None:
            fn_idx = self._enrichment_functions.index(system.detect_nodes_context)
            self._enrichment_functions[fn_idx] = enrichment(EnrichmentStage.LIGHT)\
                (lambda c: c.nodes_context.update(nodes_context))

    @property
    def working_inventory(self) -> dict:
        cluster = self.cluster_if_initialized()
        if cluster is not None:
            return cluster.inventory

        return {}

    def _store_finalized_inventory(self, finalized_inventory: dict, finalized_filename: str) -> None:
        self.finalized_inventory = finalized_inventory
        super()._store_finalized_inventory(finalized_inventory, finalized_filename)

    def cluster_if_initialized(self) -> Optional[FakeKubernetesCluster]:
        cluster = super().cluster_if_initialized()
        return None if cluster is None else cast(FakeKubernetesCluster, cluster)

    def cluster(self, stage: EnrichmentStage = EnrichmentStage.PROCEDURE) -> FakeKubernetesCluster:
        return cast(FakeKubernetesCluster, super().cluster(stage))

    def _new_cluster_instance(self, context: dict) -> FakeKubernetesCluster:
        return FakeKubernetesCluster(
            self.inventory(), context, self.procedure_inventory(),
            self.logger(),
            connection_pool=self._connection_pool, nodes_context=self._nodes_context,
            resources=self,
        )

    def insert_enrichment_function(self, near: EnrichmentFunction, stages: EnrichmentStage,
                                   fn: Callable[[KubernetesCluster], Optional[dict]],
                                   *,
                                   procedure: str = None,
                                   after: bool = False) -> None:

        enrichment_fn = enrichment(stages, procedures=None if procedure is None else [procedure])(fn)

        idx = self._enrichment_functions.index(near)
        if after:
            idx += 1
        self._enrichment_functions.insert(idx, enrichment_fn)

        self._skip_default_enrichment = None

    def enrichment_functions(self) -> List[EnrichmentFunction]:
        return self._enrichment_functions


class FakeResources(FakeClusterResources):
    def __init__(self, context: dict, inventory: dict = None,
                 *,
                 procedure_inventory: dict = None,
                 nodes_context: Dict[str, Any] = None,
                 fake_shell: FakeShell = None, fake_fs: FakeFS = None):
        super().__init__(context, nodes_context=nodes_context, fake_shell=fake_shell, fake_fs=fake_fs)
        self.inventory_filepath = None
        self.procedure_inventory_filepath = None
        self._inventory = inventory
        self._procedure_inventory = procedure_inventory

    def _store_inventory(self, inventory: dict) -> None:
        pass

    def _store_finalized_inventory(self, finalized_inventory: dict, finalized_filename: str) -> None:
        self.finalized_inventory = finalized_inventory
        utils.dump_file(self, yaml.dump(finalized_inventory), finalized_filename)


class FakeConnection(connections.Connection):

    def __init__(self, ip: str, fake_shell: FakeShell, fake_fs: FakeFS, **kw: Any):
        super().__init__(ip, **kw)
        self.fake_shell = fake_shell
        self.fake_fs = fake_fs

        command_sep = r'[=\-_]{32}'
        sep_symbol = r'\&\&|;'
        final_sep = rf" ({sep_symbol}) " \
                    rf"printf \"%s\\n\$\?\\n%s\\n\" \"({command_sep})\" \"\2\" \1 " \
                    rf"echo \"\2\" 1>\&2 \1 (sudo )?"

        self.separator_ptrn = re.compile(final_sep)

    def __setattr__(self, key: str, value: Any) -> None:
        # fabric Connection has special handling of this method. Call default behaviour for custom attributes.
        if key in ('fake_shell', 'fake_fs', 'separator_ptrn'):
            return object.__setattr__(self, key, value)
        super().__setattr__(key, value)

    def run(self, command: str, **kwargs: Any) -> fabric.runners.Result:
        return self._do("run", command, **kwargs)

    def sudo(self, command: str, **kwargs: Any) -> fabric.runners.Result:
        return self._do("sudo", command, **kwargs)

    # not implemented
    def get(self, remote_file: str, local_file: str, **kwargs: Any) -> None:  # pylint: disable=arguments-differ
        raise NotImplementedError("Stub for fabric Connection.get() is not implemented")

    def put(self, data: Union[io.BytesIO, str], filename: str, **kwargs: Any) -> None:  # pylint: disable=arguments-differ
        # It should return fabric.transfer.Result, but currently returns None.
        # Transfer Result is currently never handled.
        self.fake_fs.write(self.host, filename, data)

    def _do(self, do_type: str, original_command: str, **kwargs: Any) -> fabric.runners.Result:
        # start fake execution of commands
        commands, sep_symbol, command_sep = self._split_command(do_type, original_command)

        final_res = fabric.runners.Result(stdout="", stderr="", exited=None,
                                          connection=self, command=original_command)
        prev_exited = None
        i = 0
        for command in commands:
            found_result = self.fake_shell.find(self.host, do_type, [command])

            if found_result is None:
                raise Exception('Fake result not found for requested action type \'%s\' and command %s' % (do_type, [command]))

            timeout_exception = None
            if isinstance(found_result, BaseException):
                if i > 0:
                    raise ValueError("Exception can be thrown only for the whole command")
                elif isinstance(found_result, CommandTimedOut):
                    timeout_exception = found_result
                    found_result = found_result.result
                else:
                    raise found_result

            hide = kwargs.get('hide', False)
            if found_result.hide != hide:
                raise Exception(f"Fake result has hide={found_result.hide} while hide={hide} was requested")

            if i > 0:
                final_res.stdout += command_sep + '\n' + str(prev_exited) + '\n' + command_sep + '\n'
                final_res.stderr += command_sep + '\n'
            i += 1

            for stream_t in ('stdout', 'stderr'):
                output = getattr(found_result, stream_t)
                if output and not hide:
                    stream = getattr(sys, stream_t)
                    stream.write(output)
                    stream.flush()

                final_output = getattr(final_res, stream_t)
                setattr(final_res, stream_t, final_output + output)

            final_res.exited = prev_exited = found_result.exited

            if timeout_exception is not None:
                raise invoke.CommandTimedOut(final_res, timeout_exception.timeout)

            if prev_exited != 0 and sep_symbol != ';':
                # stop fake execution
                break

        if prev_exited == 0 or kwargs.get('warn', False):
            return final_res

        raise invoke.UnexpectedExit(final_res)

    def _split_command(self, do_type: str, command: str) -> Tuple[List[str], str, str]:
        """
        This is a reverse operation to the RemoteExecutor#_merge_actions
        """
        tokens = self.separator_ptrn.split(command)
        commands = []
        i = 0
        sep_symbol = None
        command_sep = None
        while i < len(tokens):
            commands.append(tokens[i])
            i += 1
            if i < len(tokens):
                sep_symbol = self._compare_and_return(sep_symbol, tokens[i], "Separator symbols are not equal")
                command_sep = self._compare_and_return(command_sep, tokens[i + 1], "Command separators are not equal")
                resolved_do_type = "sudo" if tokens[i + 2] == 'sudo ' else "run"
                self._compare_and_return(do_type, resolved_do_type, "Do types are not equal")
                i += 3

        return commands, sep_symbol or '', command_sep or ''

    def _compare_and_return(self, one: Optional[str], another: str, msg: str) -> str:
        if one is None or one == another:
            return another
        else:
            raise ValueError(msg)

    def close(self) -> None:
        pass


class FakeAbstractGroup(AbstractGroup[GROUP_RUN_TYPE], ABC):
    def _put_with_mv(self, local_stream: Union[bytes, str], remote_file: str,
                     backup: bool, sudo: bool, mkdir: bool, immutable: bool) -> None:
        super()._put_with_mv(local_stream, remote_file, backup=False, sudo=False, mkdir=False, immutable=False)


class FakeNodeGroup(NodeGroup, FakeAbstractGroup[RunnersGroupResult]):
    def _make_group(self, ips: Iterable[Union[str, NodeGroup]]) -> FakeNodeGroup:
        return FakeNodeGroup(ips, self.cluster)

    def _make_defer(self, executor: RemoteExecutor) -> FakeDeferredGroup:
        return FakeDeferredGroup(self.nodes, self.cluster, executor)

    def get_local_file_sha1(self, local_file: Union[bytes, str]) -> str:
        return '0'

    def get_remote_file_sha1(self, filename: str) -> Dict[str, Optional[str]]:
        return {host: '1' for host in self.nodes}


class FakeDeferredGroup(DeferredGroup, FakeAbstractGroup[Token]):
    def _make_group(self, ips: Iterable[Union[str, DeferredGroup]]) -> FakeDeferredGroup:
        return FakeDeferredGroup(ips, self.cluster, self._executor)


class FakeConnectionPool(connections.ConnectionPool):
    def __init__(self, nodes: Dict[str, dict], gateway_nodes: Dict[str, dict], hosts: List[str],
                 fake_shell: FakeShell, fake_fs: FakeFS):
        self.fake_shell = fake_shell
        self.fake_fs = fake_fs
        super().__init__(nodes, gateway_nodes, hosts)

    def _create_connection_from_details(self, ip: str, conn_details: dict,
                                        gateway: fabric.connection.Connection = None,
                                        inline_ssh_env: bool = True) -> FakeConnection:
        return FakeConnection(
            ip, self.fake_shell, self.fake_fs, gateway=gateway,
            user=conn_details.get('username', static.GLOBALS['connection']['defaults']['username']),
            port=conn_details.get('connection_port', static.GLOBALS['connection']['defaults']['port'])
        )


def create_silent_context(args: list = None, procedure: str = 'install') -> dict:
    args = list(args) if args else []
    # todo probably increase logging level to get rid of spam in logs.

    context: dict = procedures.import_procedure(procedure).create_context(args)
    context['preserve_inventory'] = False
    context['make_finalized_inventory'] = False
    context['load_inventory_silent'] = True

    parsed_args: dict = context['execution_arguments']
    parsed_args['disable_dump'] = True
    del parsed_args['ansible_inventory_location']

    return context


def new_resources(inventory: dict, procedure_inventory: dict = None, context: dict = None,
                  nodes_context: dict = None) -> FakeResources:
    if context is None:
        context = create_silent_context()

    nds_context = generate_nodes_context(inventory, procedure_inventory, context)
    if nodes_context is not None:
        nds_context.update(nodes_context)

    return FakeResources(context, inventory,
                         procedure_inventory=procedure_inventory, nodes_context=nds_context)


def new_cluster(inventory: dict, procedure_inventory: dict = None, context: dict = None,
                nodes_context: dict = None) -> FakeKubernetesCluster:
    res = new_resources(inventory, procedure_inventory, context, nodes_context)
    try:
        return res.cluster()
    except errors.FailException as exc:
        if exc.reason is not None:
            raise exc.reason

        raise


def generate_node_context(*,
                          online: bool = True, accessible: bool = True, sudo: str = 'Root',
                          os_name: str = 'centos', os_version: str = '7.9',
                          net_interface: str = 'eth0') -> dict:
    os_family = system.detect_os_family_by_name_version(os_name, os_version)

    if not online:
        accessible = False
    if not accessible:
        sudo = 'No'
        os_name, os_version, os_family, net_interface = tuple('<undefined>' for _ in range(4))

    return {
        'access': {
            'online': online,
            'accessible': accessible,
            'sudo': sudo
        },
        'active_interface': net_interface,
        'os': {
            'name': os_name,
            'family': os_family,
            'version': os_version
        }
    }


def generate_nodes_context(inventory: dict, procedure_inventory: dict = None, context: dict = None,
                           *,
                           os_name: str = 'centos', os_version: str = '7.9',
                           net_interface: str = 'eth0') -> dict:
    procedure = 'install' if context is None else context['initial_procedure']
    if procedure_inventory is None:
        procedure_inventory = {}

    nodes = inventory['nodes']
    if procedure == 'add_node':
        nodes = itertools.chain(nodes, procedure_inventory.get('nodes', []))

    context = {}
    for node in nodes:
        connect_to = node['internal_address']
        if node.get('address'):
            connect_to = node['address']
        context[connect_to] = generate_node_context(os_name=os_name, os_version=os_version, net_interface=net_interface)

    return context


def generate_inventory(balancer: _ROLE_SPEC = 1, control_plane: _ROLE_SPEC = 1, worker: _ROLE_SPEC = 1,
                       keepalived: _ROLE_SPEC = 0, haproxy_mntc: _ROLE_SPEC = 0) -> dict:
    inventory: dict = {
        'node_defaults': {
            'keyfile': '/dev/null',
            'username': 'anonymous'
        },
        'nodes': [],
        'services': {
            'cri': {}
        },
        'cluster_name': 'k8s.fake.local'
    }

    id_roles_map: Dict[str, List[str]] = {}

    for role_name, item in (('balancer', balancer), ('control-plane', control_plane), ('worker', worker)):

        if isinstance(item, int):
            item = [f'{role_name}-{i + 1}' for i in range(item)]

        for id_ in item:
            id_roles_map.setdefault(id_, []).append(role_name)

    ip_i = 0

    for id_, roles in id_roles_map.items():
        ip_i = ip_i + 1
        if "control-plane" in roles and worker == 0:
            roles.append('worker')
        inventory['nodes'].append({
            'name': id_,
            'address': '10.101.1.%s' % ip_i,
            'internal_address': '192.168.0.%s' % ip_i,
            'roles': roles
        })

    ip_i = 0
    vrrp_ips: List[Union[str, dict]] = []

    if isinstance(keepalived, list):
        vrrp_ips.extend(deepcopy(keepalived))
    elif isinstance(keepalived, int) and keepalived > 0:
        for _ in range(keepalived):
            ip_i = ip_i + 1
            vrrp_ips.append('10.101.2.%s' % ip_i)

    if isinstance(haproxy_mntc, list):
        vrrp_ips.extend(deepcopy(haproxy_mntc))
    elif isinstance(haproxy_mntc, int) and haproxy_mntc > 0:
        for _ in range(haproxy_mntc):
            ip_i = ip_i + 1
            vrrp_ips.append({
                'ip': '10.101.2.%s' % ip_i,
                'params': {
                    'maintenance-type': 'not bind'
                }
            })

    if haproxy_mntc:
        inventory['services'] = {
            'loadbalancer' : {
                'haproxy': {
                    'maintenance_mode': True
                }
            }
        }

    inventory['vrrp_ips'] = vrrp_ips

    return inventory


def generate_procedure_inventory(procedure: str) -> dict:
    procedure_inventory: dict = {}
    # set some commonly required properties
    if procedure == 'manage_pss':
        procedure_inventory['pss'] = {'pod-security': 'enabled'}

    return procedure_inventory


def create_nodegroup_result_by_hosts(cluster: KubernetesCluster, results: Dict[str, GenericResult]) -> NodeGroupResult:
    return NodeGroupResult(cluster, results)


def create_exception_result(group_: AbstractGroup[RunResult], exception: Exception) -> NodeGroupResult:
    hosts_to_result = create_hosts_exception_result(group_.get_hosts(), exception)
    return create_nodegroup_result_by_hosts(group_.cluster, hosts_to_result)


def create_hosts_exception_result(hosts: List[str], exception: Exception) -> Dict[str, GenericResult]:
    return {host: exception for host in hosts}


def create_nodegroup_result(group_: AbstractGroup[RunResult], stdout: str = '', stderr: str = '', hide: bool = True,
                            code: int = 0, timeout: int = None) -> NodeGroupResult:
    hosts_to_result = create_hosts_result(group_.get_hosts(), stdout, stderr, hide, code, timeout)
    return create_nodegroup_result_by_hosts(group_.cluster, hosts_to_result)


def create_hosts_result(hosts: List[str], stdout: str = '', stderr: str = '', hide: bool = True,
                        code: int = 0, timeout: int = None) -> Dict[str, GenericResult]:
    # each host should have its own result instance.
    return {host: create_result(stdout, stderr, hide, code, timeout) for host in hosts}


def create_result(stdout: str = '', stderr: str = '', hide: bool = True,
                  code: int = 0, timeout: int = None) -> GenericResult:
    # command and 'hide' option will be later replaced with actual
    result = RunnersResult(["fake command"], [code], stdout=stdout, stderr=stderr, hide=hide)
    if timeout is None:
        return result

    return CommandTimedOut(result, timeout)


def new_scheme(scheme: dict, role: str, number: int) -> dict:
    scheme = deepcopy(scheme)
    scheme[role] = number
    return scheme


FULLHA: Dict[str, _ROLE_SPEC] = {'balancer': 1, 'control_plane': 3, 'worker': 3}
FULLHA_KEEPALIVED: Dict[str, _ROLE_SPEC] = {'balancer': 2, 'control_plane': 3, 'worker': 3, 'keepalived': 1}
FULLHA_NOBALANCERS: Dict[str, _ROLE_SPEC] = {'balancer': 0, 'control_plane': 3, 'worker': 3}
ALLINONE: Dict[str, _ROLE_SPEC] = {
    'control_plane': 1, 'balancer': ['control-plane-1'], 'worker': ['control-plane-1'],
    'keepalived': 1}
MINIHA: Dict[str, _ROLE_SPEC] = {'control_plane': 3}
MINIHA_KEEPALIVED: Dict[str, _ROLE_SPEC] = {
    'control_plane': 3,
    'balancer': ['control-plane-1', 'control-plane-2', 'control-plane-3'],
    'worker': ['control-plane-1', 'control-plane-2', 'control-plane-3'],
    'keepalived': 1}
NON_HA_BALANCER: Dict[str, _ROLE_SPEC] = {
    'balancer': 1, 'control_plane': 3, 'worker': ['control-plane-1', 'control-plane-2', 'control-plane-3']}
