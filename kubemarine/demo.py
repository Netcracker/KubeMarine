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

import io
from typing import List, Dict, Union, Any

import fabric
from invoke import UnexpectedExit

from kubemarine.core import cluster, group, flow
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.connections import Connections
from kubemarine.core.group import NodeGroup, _HostToResult, NodeGroupResult
from kubemarine.core.executor import RemoteExecutor


class FakeShell:
    def __init__(self, _cluster):
        self.cluster = _cluster
        self.results: List[Dict[str, Union[NodeGroupResult, Any]]] = []
        self.history = []

    def reset(self):
        self.results = []
        self.history = []

    def add(self, result: NodeGroupResult, do_type, args, usage_limit=0):
        args.sort()

        result = {
            'result': result,
            'do_type': do_type,
            'args': args,
            'used_times': 0
        }

        if usage_limit > 0:
            result['usage_limit'] = usage_limit

        self.results.append(result)

    def find(self, do_type, args, kwargs):
        # TODO: Support kwargs
        if isinstance(args, tuple):
            args = list(args)
        for i, item in enumerate(self.results):
            if item['do_type'] == do_type and item['args'] == args:
                self.history.append(item)
                self.results[i]['used_times'] += 1
                if item.get('usage_limit') is not None:
                    self.results[i]['usage_limit'] -= 1
                    if self.results[i]['usage_limit'] < 1:
                        del self.results[i]
                return item['result']
        return None

    # covered by test.test_demo.TestFakeShell.test_calculate_calls
    def history_find(self, do_type, args):
        # TODO: Support kwargs
        result = []
        if isinstance(args, tuple):
            args = list(args)
        for item in self.history:
            if item['do_type'] == do_type and item['args'] == args:
                result.append(item)
        return result

    def is_called(self, do_type: str, args: list) -> bool:
        """
        Returns true if the specified command has already been executed in FakeShell. If there is no such command in the
        FakeShell expected ones, or if several commands are found, exceptions will be thrown.
        :param do_type: The type of required command
        :param args: Required command arguments
        :return: Boolean
        """
        found_entry = self.history_find(do_type, args)
        if not found_entry:
            raise Exception('Failed to found entry %s %s in history' % (do_type, str(args)))
        elif len(found_entry) > 1:
            raise Exception('Too many entries found for request in history: %s %s' % (do_type, str(args)))
        return self.history_find(do_type, args)[0]['used_times'] > 0


class FakeFS:
    def __init__(self, _cluster):
        self.cluster = _cluster
        self.storage = {}

    def reset(self):
        self.storage = {}

    def reset_host(self, host):
        self.storage[host] = {}

    # covered by test.test_demo.TestFakeFS.test_put_string
    # covered by test.test_demo.TestFakeFS.test_put_stringio
    def write(self, host, filename, data):
        if isinstance(data, io.StringIO):
            data = data.getvalue()
        if self.storage.get(host) is None:
            self.storage[host] = {}
        self.storage[host][filename] = data

    # covered by test.test_demo.TestFakeFS.test_write_file_to_cluster
    def group_write(self, _group, filename, data):
        for host, connection in _group.nodes.items():
            self.write(host, filename, data)

    # covered by test.test_demo.TestFakeFS.test_put_string
    # covered by test.test_demo.TestFakeFS.test_get_nonexistent
    def read(self, host, filename):
        return self.storage.get(host, {}).get(filename)

    # covered by test.test_demo.TestFakeFS.test_write_file_to_cluster
    def group_read(self, _group, filename):
        result = {}
        for host, connection in _group.nodes.items():
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


class FakeKubernetesCluster(cluster.KubernetesCluster):

    def __init__(self, inventory, execution_arguments):
        super().__init__(inventory, execution_arguments)
        self.fake_shell = FakeShell(self)
        self.fake_fs = FakeFS(self)

    def make_group(self, ips) -> NodeGroup:
        nodegroup = super().make_group(ips)
        return FakeNodeGroup(nodegroup.nodes, self)

    def finish(self):
        return


class FakeNodeGroupResult(group.NodeGroupResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class FakeNodeGroup(group.NodeGroup):

    def __init__(self, connections: Connections, cluster_: FakeKubernetesCluster):
        super().__init__(connections, cluster_)
        self.cluster = cluster_

    def _do(self, do_type, nodes: Connections, is_async, *args, **kwargs) -> _HostToResult:

        if do_type in ['sudo', 'run']:
            found_result = self.cluster.fake_shell.find(do_type, args, kwargs)

            if found_result is None:
                raise Exception('Fake result not found for requested action type \'%s\' and args %s' % (do_type, args))

            found_result = {((isinstance(host, fabric.connection.Connection) and host.host) or host): result for host, result in found_result.items() if (isinstance(host, fabric.connection.Connection) and host.host in nodes.keys()) or host in nodes.keys()}

            if not found_result:
                raise Exception('Fake results were found, but all of them were filtered')

            for host, result in found_result.items():
                if isinstance(result, UnexpectedExit) and kwargs.get('warn', False):
                    found_result[host] = result.result

            # Remote Executor support code
            gre = RemoteExecutor(self.cluster)
            executor = gre._get_active_executor()
            batch_results = {}
            for host, result in found_result.items():
                batch_results[host] = {0: result}
            executor.results.append(batch_results)

            return found_result

        raise Exception('Unsupported do type')

    def put(self, *args, **kwargs):
        self.cluster.fake_fs.group_write(self, args[1], args[0])

    def disconnect(self, hosts: List[str] = None):
        return

    def _make_result(self, results: _HostToResult) -> FakeNodeGroupResult:
        group_result = FakeNodeGroupResult(self.cluster, results)
        return group_result


def new_cluster(inventory, procedure=None, fake=True,
                os_name='centos', os_version='7.9', net_interface='eth0'):

    context = flow.create_context({
        'disable_dump': True,
        'nodes': []
    }, procedure=procedure)

    os_family = None

    if os_name in ['centos', 'rhel']:
        os_family = 'rhel'
    elif os_name in ['ubuntu', 'debian']:
        os_family = 'debian'

    for node in inventory['nodes']:
        node_context = {
            'name': node['name'],
            'online': True,
            'hasroot': True,
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
        context['nodes'][connect_to] = node_context

    context['os'] = os_family

    # It is possible to disable FakeCluster and create real cluster Object for some business case
    if fake:
        return FakeKubernetesCluster(inventory, context)
    else:
        return KubernetesCluster(inventory, context)


def generate_inventory(balancer=1, master=1, worker=1, keepalived=0):
    inventory = {
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

    if isinstance(keepalived, int):
        ips = []
        if keepalived > 0:
            for i in range(0, keepalived):
                ips.append('10.101.2.%s' % (i + 1))
        keepalived = ips

    inventory['vrrp_ips'] = keepalived

    return inventory


def create_exception_result(group_: NodeGroup, exception: Exception) -> NodeGroupResult:
    return NodeGroupResult(group_.cluster, {host: exception for host in group_.nodes.keys()})


def create_nodegroup_result(group_: NodeGroup, stdout='', stderr='', code=0) -> NodeGroupResult:
    results = {}
    for host, cxn in group_.nodes.items():
        results[host] = fabric.runners.Result(stdout=stdout, stderr=stderr, exited=code, connection=cxn)
        if code == -1:
            results[host] = UnexpectedExit(results[host])
    return NodeGroupResult(group_.cluster, results)


def empty_action(*args, **kwargs) -> None:
    """
    A dummy method that does nothing
    :return: None
    """
    pass


FULLHA = {'balancer': 1, 'master': 3, 'worker': 3}
FULLHA_KEEPALIVED = {'balancer': 2, 'master': 3, 'worker': 3, 'keepalived': 1}
FULLHA_NOBALANCERS = {'balancer': 0, 'master': 3, 'worker': 3}
ALLINONE = {'master': 1}
MINIHA = {'master': 3}
MINIHA_KEEPALIVED = {'master': 3, 'balancer': ['master-1', 'master-2', 'master-3'],
                     'worker': ['master-1', 'master-2', 'master-3'], 'keepalived': 1}
