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
import argparse
import io
import re
import threading
from copy import deepcopy
from typing import List, Dict, Union, Any, IO

import fabric
from invoke import UnexpectedExit

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core import group, flow, connections
from kubemarine.core.connections import Connections
from kubemarine.core.group import NodeGroup, NodeGroupResult, _GenericResult, _HostToResult
from kubemarine.core.resources import DynamicResources

ShellResult = Dict[str, Union[NodeGroupResult, Any]]


class FakeShell:
    def __init__(self):
        self.results: Dict[str, List[ShellResult]] = {}
        self.history: Dict[str, List[ShellResult]] = {}
        self._lock = threading.Lock()

    def __deepcopy__(self, memodict={}):
        cls = self.__class__
        result = cls.__new__(cls)
        memodict[id(self)] = result
        result.results = deepcopy(self.results, memodict)
        result.history = deepcopy(self.history, memodict)
        result._lock = threading.Lock()
        return result

    def reset(self):
        self.results = {}
        self.history = {}

    def add(self, results: Union[NodeGroupResult, _HostToResult], do_type, args, usage_limit=0):
        args.sort()

        for host, result in results.items():
            host = host.host if isinstance(host, fabric.connection.Connection) else host
            result = {
                'result': result,
                'do_type': do_type,
                'args': args,
                'used_times': 0
            }

            if usage_limit > 0:
                result['usage_limit'] = usage_limit

            self.results.setdefault(host, []).append(result)

    def find(self, host: str, do_type, args, kwargs) -> _GenericResult:
        # TODO: Support kwargs
        with self._lock:
            if isinstance(args, tuple):
                args = list(args)
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
    def history_find(self, host: str, do_type, args):
        # TODO: Support kwargs
        result = []
        if isinstance(args, tuple):
            args = list(args)
        for item in self.history.get(host, []):
            if item['do_type'] == do_type and item['args'] == args:
                result.append(item)
        return result

    def is_called_each(self, hosts: List[str], do_type: str, args: list) -> bool:
        return all((self.is_called(host, do_type, args) for host in hosts))

    def is_called(self, host: str, do_type: str, args: list) -> bool:
        """
        Returns true if the specified command has already been executed in FakeShell for the specified connection.
        :param host: host to check, for which the desirable command should have been executed.
        :param do_type: The type of required command
        :param args: Required command arguments
        :return: Boolean
        """
        found_entries = self.history_find(host, do_type, args)
        return sum(found_entry['used_times'] for found_entry in found_entries) > 0


class FakeFS:
    def __init__(self):
        self.storage: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()

    def __deepcopy__(self, memodict={}):
        cls = self.__class__
        result = cls.__new__(cls)
        memodict[id(self)] = result
        result.storage = deepcopy(self.storage, memodict)
        result._lock = threading.Lock()
        return result

    def reset(self):
        self.storage = {}

    def reset_host(self, host):
        self.storage[host] = {}

    # covered by test.test_demo.TestFakeFS.test_put_string
    # covered by test.test_demo.TestFakeFS.test_put_stringio
    # covered by test.test_demo.TestFakeFS.test_write_file_to_cluster
    def write(self, host, filename, data):
        with self._lock:
            if isinstance(data, io.BytesIO):
                data = data.getvalue().decode('utf-8')
            elif isinstance(data, str):
                # this is for self-testing purpose
                pass
            elif isinstance(data, io.IOBase):
                data = data.read().decode('utf-8')
            else:
                raise ValueError("Unsupported data type " + str(type(data)))
            if self.storage.get(host) is None:
                self.storage[host] = {}
            self.storage[host][filename] = data

    # covered by test.test_demo.TestFakeFS.test_put_string
    # covered by test.test_demo.TestFakeFS.test_get_nonexistent
    def read(self, host, filename):
        return self.storage.get(host, {}).get(filename)

    # covered by test.test_demo.TestFakeFS.test_write_file_to_cluster
    def read_all(self, hosts: List[str], filename):
        result = {}
        for host in hosts:
            result[host] = self.read(host, filename)
        return result

    def ls(self, host, path):
        for _path in list(self.storage.get(host, {}).keys()):
            # TODO
            pass

    def rm(self, host, path):
        for _path in list(self.storage.get(host, {}).keys()):
            if path in _path:
                del self.storage[host][_path]


class FakeKubernetesCluster(KubernetesCluster):

    def __init__(self, *args, **kwargs):
        self.fake_shell = kwargs.pop("fake_shell", FakeShell())
        self.fake_fs = kwargs.pop("fake_fs", FakeFS())
        super().__init__(*args, **kwargs)
        self._connection_pool = FakeConnectionPool(self)

    def make_group(self, ips) -> NodeGroup:
        nodegroup = super().make_group(ips)
        return FakeNodeGroup(nodegroup.nodes, self)

    def dump_finalized_inventory(self):
        return

    def preserve_inventory(self):
        return


class FakeResources(DynamicResources):
    def __init__(self, context, raw_inventory: dict, procedure_inventory: dict = None,
                 cluster: KubernetesCluster = None,
                 fake_shell: FakeShell = None, fake_fs: FakeFS = None):
        super().__init__(context, True)
        self.inventory_filepath = None
        self.procedure_inventory_filepath = None
        self._raw_inventory = raw_inventory
        self._formatted_inventory = raw_inventory
        self._procedure_inventory = procedure_inventory
        self._cluster = cluster
        if cluster:
            self._logger = cluster.log
        self._fake_shell = fake_shell if fake_shell else FakeShell()
        self._fake_fs = fake_fs if fake_fs else FakeFS()

    def _new_cluster_instance(self, context: dict):
        return FakeKubernetesCluster(self.raw_inventory(), context,
                                     procedure_inventory=self.procedure_inventory(),
                                     logger=self.logger(),
                                     fake_shell=self._fake_shell, fake_fs=self._fake_fs)


class FakeConnection(fabric.connection.Connection):

    def __init__(self, ip, cluster: FakeKubernetesCluster, **kw):
        super().__init__(ip, **kw)
        self.fake_shell = cluster.fake_shell
        self.fake_fs = cluster.fake_fs

        command_sep = r'[=\-_]{32}'
        sep_symbol = r'\&\&|;'
        final_sep = rf" ({sep_symbol}) " \
                    rf"echo \"({command_sep})\" \1 " \
                    rf"echo \$\? \1 " \
                    rf"echo \"\2\" \1 " \
                    rf"echo \"\2\" 1>\&2 \1 (sudo )?"

        self.separator_ptrn = re.compile(final_sep)

    def __setattr__(self, key, value):
        # fabric Connection has special handling of this method. Call default behaviour for custom attributes.
        if key in ('fake_shell', 'fake_fs', 'separator_ptrn'):
            return object.__setattr__(self, key, value)
        super().__setattr__(key, value)

    def run(self, command, **kwargs) -> fabric.runners.Result:
        return self._do("run", command, **kwargs)

    def sudo(self, command, **kwargs) -> fabric.runners.Result:
        return self._do("sudo", command, **kwargs)

    # not implemented
    def get(self, *args, **kwargs):
        return self._do("get", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._do("put", *args, **kwargs)

    def _do(self, do_type, *args, **kwargs) -> fabric.runners.Result:
        if do_type in ['sudo', 'run']:
            # start fake execution of commands
            command = list(args)[0]
            commands, sep_symbol, command_sep = self._split_command(do_type, command)

            stdout = ""
            stderr = ""
            prev_exited = None
            i = 0
            for command in commands:
                found_result = self.fake_shell.find(self.host, do_type, [command], kwargs)

                if found_result is None:
                    raise Exception('Fake result not found for requested action type \'%s\' and command %s' % (do_type, [command]))

                if isinstance(found_result, Exception):
                    if i > 0:
                        raise ValueError("Exception can be thrown only for the whole command")
                    else:
                        raise found_result

                if i > 0:
                    stdout += command_sep + '\n' + str(prev_exited) + '\n' + command_sep + '\n'
                    stderr += command_sep + '\n'
                i += 1

                stdout += found_result.stdout
                stderr += found_result.stderr
                prev_exited = found_result.exited
                if prev_exited != 0:
                    if sep_symbol == ';':
                        prev_exited = 0  # todo bug of RemoteExecutor
                    else:
                        # stop fake execution
                        break

            final_res = fabric.runners.Result(stdout=stdout, stderr=stderr, exited=prev_exited, connection=self)
            if prev_exited == 0 or kwargs.get('warn', False):
                return final_res

            raise UnexpectedExit(final_res)

        elif do_type == 'put':
            # It should return fabric.transfer.Result, but currently returns None.
            # Transfer Result is currently never handled.
            return self.fake_fs.write(self.host, args[1], args[0])

        raise Exception('Unsupported do type')

    def _split_command(self, do_type, command: str):
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

        return commands, sep_symbol, command_sep

    def _compare_and_return(self, one, another, msg):
        if one is None or one == another:
            return another
        else:
            raise ValueError(msg)

    def close(self):
        pass


class FakeNodeGroup(group.NodeGroup):

    def __init__(self, connections: Connections, cluster_: FakeKubernetesCluster):
        super().__init__(connections, cluster_)

    def get_local_file_sha1(self, filename):
        return '0'

    def get_remote_file_sha1(self, filename):
        return {host: '1' for host in self.nodes.keys()}

    def _put(self, local_stream: IO, remote_file: str, **kwargs):
        kwargs.pop("sudo", None)
        kwargs.pop("backup", None)
        kwargs.pop("immutable", None)
        super()._put(local_stream, remote_file, **kwargs)


class FakeConnectionPool(connections.ConnectionPool):
    def __init__(self, cluster: FakeKubernetesCluster):
        super().__init__(cluster)
        self.cluster = cluster

    def _create_connection_from_details(self, ip: str, conn_details: dict, gateway=None, inline_ssh_env=True):
        return FakeConnection(
            ip, self.cluster,
            user=conn_details.get('username', self._env.globals['connection']['defaults']['username']),
            port=conn_details.get('connection_port', self._env.globals['connection']['defaults']['port'])
        )


def create_silent_context(args: list = None, parser: argparse.ArgumentParser = None, procedure: str = None):
    args = list(args) if args else []
    # todo probably increase logging level to get rid of spam in logs.
    if '--disable-dump' not in args:
        args.append('--disable-dump')

    if parser is None:
        parser = flow.new_common_parser("Help text")
    context = flow.create_context(parser, args, procedure=procedure)
    del context['execution_arguments']['ansible_inventory_location']
    context['preserve_inventory'] = False

    return context


def new_cluster(inventory, procedure_inventory=None, context: dict = None,
                fake=True) -> Union[KubernetesCluster, FakeKubernetesCluster]:
    if context is None:
        context = create_silent_context()

    nodes_context = generate_nodes_context(inventory)
    nodes_context.update(context['nodes'])
    context['nodes'] = nodes_context

    # It is possible to disable FakeCluster and create real cluster Object for some business case
    if fake:
        cluster = FakeKubernetesCluster(inventory, context, procedure_inventory=procedure_inventory)
    else:
        cluster = KubernetesCluster(inventory, context, procedure_inventory=procedure_inventory)

    cluster.enrich()
    return cluster


def generate_nodes_context(inventory: dict, os_name='centos', os_version='7.9', net_interface='eth0') -> dict:
    os_family = None

    if os_name in ['centos', 'rhel']:
        os_family = 'rhel'
    elif os_name in ['ubuntu', 'debian']:
        os_family = 'debian'

    context = {}
    for node in inventory['nodes']:
        node_context = {
            'access': {
                'online': True,
                'accessible': True,
                'sudo': 'Root'
            },
            'active_interface': net_interface,
            'os': {
                'name': os_name,
                'family': os_family,
                'version': os_version
            }
        }
        connect_to = node['internal_address']
        if node.get('address'):
            connect_to = node['address']
        context[connect_to] = node_context

    return context


def generate_inventory(balancer=1, master=1, worker=1, keepalived=0, haproxy_mntc=0):
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

    id_roles_map = {}

    for role_name in ['balancer', 'master', 'worker']:

        item = locals()[role_name]

        if isinstance(item, int):
            ids = []
            if item > 0:
                for i in range(0, item):
                    ids.append('%s-%s' % (role_name, i + 1))
            item = ids

        if item:
            for id_ in item:
                roles = id_roles_map.get(id_)
                if roles is None:
                    roles = []
                roles.append(role_name)
                id_roles_map[id_] = roles

    ip_i = 0

    for id_, roles in id_roles_map.items():
        ip_i = ip_i + 1
        if "master" in roles and worker == 0:
            roles.append('worker')
        inventory['nodes'].append({
            'name': id_,
            'address': '10.101.1.%s' % ip_i,
            'internal_address': '192.168.0.%s' % ip_i,
            'roles': roles
        })

    ip_i = 0
    vrrp_ips = []

    if isinstance(keepalived, list):
        vrrp_ips.append(deepcopy(keepalived))
    elif isinstance(keepalived, int) and keepalived > 0:
        for _ in range(keepalived):
            ip_i = ip_i + 1
            vrrp_ips.append('10.101.2.%s' % ip_i)

    if isinstance(haproxy_mntc, list):
        vrrp_ips.append(deepcopy(haproxy_mntc))
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


def create_exception_result(group_: NodeGroup, exception: Exception) -> NodeGroupResult:
    return NodeGroupResult(group_.cluster, create_hosts_exception_result(group_.get_hosts(), exception))


def create_hosts_exception_result(hosts: List[str], exception: Exception) -> _HostToResult:
    return {host: exception for host in hosts}


def create_nodegroup_result(group_: NodeGroup, stdout='', stderr='', code=0) -> NodeGroupResult:
    return NodeGroupResult(group_.cluster, create_hosts_result(group_.get_hosts(), stdout, stderr, code))


def create_hosts_result(hosts: List[str], stdout='', stderr='', code=0) -> _HostToResult:
    # each host should have its own result instance.
    return {host: create_result(stdout, stderr, code) for host in hosts}


def create_result(stdout='', stderr='', code=0) -> _GenericResult:
    # connection will be later replaced to fake
    return fabric.runners.Result(stdout=stdout, stderr=stderr, exited=code, connection=None)


def empty_action(*args, **kwargs) -> None:
    """
    A dummy method that does nothing
    :return: None
    """
    pass


def new_scheme(scheme: dict, role: str, number: int):
    scheme = deepcopy(scheme)
    scheme[role] = number
    return scheme


FULLHA = {'balancer': 1, 'master': 3, 'worker': 3}
FULLHA_KEEPALIVED = {'balancer': 2, 'master': 3, 'worker': 3, 'keepalived': 1}
FULLHA_NOBALANCERS = {'balancer': 0, 'master': 3, 'worker': 3}
ALLINONE = {'master': 1, 'balancer': ['master-1'], 'worker': ['master-1'], 'keepalived': 1}
MINIHA = {'master': 3}
MINIHA_KEEPALIVED = {'master': 3, 'balancer': ['master-1', 'master-2', 'master-3'],
                     'worker': ['master-1', 'master-2', 'master-3'], 'keepalived': 1}
NON_HA_BALANCER = {'balancer': 1, 'master': 3, 'worker': ['master-1', 'master-2', 'master-3']}
