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
import os
import random
import uuid
from abc import ABC, abstractmethod
from types import FunctionType
from typing import (
    Callable, Dict, List, Union, Any, TypeVar, Mapping, Iterator, Optional, Iterable, Generic, Set, cast
)

from kubemarine.core import utils, log, errors
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.executor import (
    RawExecutor, Token, GenericResult, RunnersResult, HostToResult, Callback, TokenizedResult,
)

NodeConfig = Dict[str, Any]
GroupFilter = Union[Callable[[NodeConfig], bool], NodeConfig]

_RESULT = TypeVar('_RESULT', bound=GenericResult, covariant=True)
_T = TypeVar('_T')


class GenericGroupResult(Mapping[str, _RESULT]):

    def __init__(self, cluster: object, results: Mapping[str, _RESULT]) -> None:
        self.cluster = cluster
        self._result: Dict[str, _RESULT] = dict(results)

    def __getitem__(self, host: str) -> _RESULT:
        return self._result[host]

    def __len__(self) -> int:
        return len(self._result)

    def __iter__(self) -> Iterator[str]:
        return iter(self._result)

    def get_simple_out(self) -> str:
        return self.get_simple_result().stdout

    def get_simple_result(self) -> RunnersResult:
        if len(self) != 1:
            raise NotImplementedError("Simple result can be returned only for NodeGroupResult consisted of "
                                      "exactly one node, but %s were provided." % list(self.keys()))

        res = list(self.values())[0]
        if not isinstance(res, RunnersResult):
            raise NotImplementedError("It does not make sense to return simple output for result of type %s"
                                      % type(res))

        return res

    def __str__(self) -> str:
        host_outputs = []
        for host, result in self.items():
            output = f"{host}:"

            if isinstance(result, RunnersResult):
                output += f" code={result.repr_code()}"
                repr_out = result.repr_out()
                if repr_out:
                    output += '\n\t' + repr_out.replace('\n', '\n\t')

            # The exception may be only the last in the list. We are also sure to have at least one result per node.
            if isinstance(result, Exception):
                exception = errors.wrap_kme_exception(result)
                output += '\n\t' + str(exception).replace('\n', '\n\t')

            host_outputs.append(output)

        return "\n".join(host_outputs)

    def _make_group(self, hosts: Iterable[str]) -> NodeGroup:
        return NodeGroup(hosts, self.cluster)

    def get_group(self) -> NodeGroup:
        """
        Forms and returns a new group from node results
        :return: NodeGroup
        """
        return self._make_group(self.keys())

    def is_any_has_code(self, code: int) -> bool:
        """
        Returns true if some group result has an exit code equal to the given one. Exceptions and other objects in
        results will be ignored.
        :param code: The code with which the result codes will be compared
        :return: Boolean
        """
        for result in self.values():
            if isinstance(result, RunnersResult) and result.exited == code:
                return True
        return False

    def is_any_failed(self) -> bool:
        """
        Returns true if at least one result in the group finished with non-zero code
        :return: Boolean
        """
        return len(self.get_failed_hosts_list()) > 0

    def get_failed_hosts_list(self) -> List[str]:
        """
        Returns a list of hosts whose result finished with non-zero code
        :return: List with hosts
        """
        failed_hosts: List[str] = []
        for host, result in self.items():
            if isinstance(result, RunnersResult) and result.failed:
                failed_hosts.append(host)
        return failed_hosts

    def get_failed_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that either exited with an exception, or the exit code is equals 1
        :return: NodeGroup:
        """
        nodes_list = self.get_failed_hosts_list()
        return self._make_group(nodes_list)

    def get_hosts_list_where_value_in_stdout(self, value: str) -> List[str]:
        """
        Returns a list of hosts that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stdout.
        :return: List with hosts
        """
        hosts_with_stderr_value: List[str] = []
        for host, result in self.items():
            if isinstance(result, RunnersResult) and value in result.stdout:
                hosts_with_stderr_value.append(host)
        return hosts_with_stderr_value

    def get_hosts_list_where_value_in_stderr(self, value: str) -> List[str]:
        """
        Returns a list of hosts that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: List with hosts
        """
        hosts_with_stderr_value: List[str] = []
        for host, result in self.items():
            if isinstance(result, RunnersResult) and value in result.stderr:
                hosts_with_stderr_value.append(host)
        return hosts_with_stderr_value

    def get_nodes_group_where_value_in_stdout(self, value: str) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that contains the given string value in results stdout.
        :param value: The string value to be found in the nodes results stdout.
        :return: NodeGroup
        """
        nodes_list = self.get_hosts_list_where_value_in_stdout(value)
        return self._make_group(nodes_list)

    def get_nodes_group_where_value_in_stderr(self, value: str) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: NodeGroup
        """
        nodes_list = self.get_hosts_list_where_value_in_stderr(value)
        return self._make_group(nodes_list)

    def stdout_contains(self, value: str) -> bool:
        """
        Checks for the presence of the given string in all results stdout.
        :param value: The string value to be found in the nodes results stdout.
        :return: true if string presented
        """
        return len(self.get_hosts_list_where_value_in_stdout(value)) > 0

    def stderr_contains(self, value: str) -> bool:
        """
        Checks for the presence of the given string in all results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: true if string presented
        """
        return len(self.get_hosts_list_where_value_in_stderr(value)) > 0

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        if not isinstance(other, GenericGroupResult):
            return False

        if len(self) != len(other):
            return False

        for host, result in self.items():
            compared_result = other.get(host)
            if compared_result is None:
                return False

            if not isinstance(result, RunnersResult) or not isinstance(compared_result, RunnersResult):
                raise NotImplementedError('Currently only instances of RunnersResult can be compared')

            if result != compared_result:
                return False

        return True

    def __ne__(self, other: object) -> bool:
        return not self == other


class NodeGroupResult(GenericGroupResult[GenericResult]):
    pass


class RunnersGroupResult(GenericGroupResult[RunnersResult]):
    pass


class CollectorCallback(Callback):
    def __init__(self, cluster: object) -> None:
        self.cluster = cluster
        self.results: Dict[str, List[RunnersResult]] = {}
        """
        List of collected results for each host.
        If all commands are exited for the particular host, the number and order of results
        correspond to the number and order of the queued commands,
        for which the given callback was requested.
        """
        self._result: Optional[RunnersGroupResult] = None

    def accept(self, host: str, token: Token, result: RunnersResult) -> None:
        self.results.setdefault(host, []).append(result)
        self._result = None

    @property
    def result(self) -> RunnersGroupResult:
        """
        Merges the collected `results` into the single RunnersGroupResult instance.
        This can be useful to check merged output of the commands.

        Note that if the result of more than one command is merged,
        one SHOULD NOT use `RunnersResult.exited` and `RunnersResult.command`,
        as the exit code and command of few commands are undefined.

        :return: merged RunnersGroupResult instance.
        """
        if self._result is None:
            self._result = RunnersGroupResult(
                self.cluster,
                {host: RunnersResult.merge(results) for host, results in self.results.items()}
            )

        return self._result


RunResult = Union[RunnersGroupResult, Token]
GROUP_RUN_TYPE = TypeVar('GROUP_RUN_TYPE', bound=RunResult, covariant=True)
GROUP_SELF = TypeVar('GROUP_SELF', bound='AbstractGroup[Union[RunnersGroupResult, Token]]')


class AbstractGroup(Generic[GROUP_RUN_TYPE], ABC):
    def __init__(self, ips: Iterable[Union[str, GROUP_SELF]], cluster: object):
        from kubemarine.core.cluster import KubernetesCluster

        self.cluster = cast(KubernetesCluster, cluster)
        self.nodes: Set[str] = set()
        for ip in ips:
            if isinstance(ip, self.__class__):
                for host in ip.nodes:
                    self.nodes.add(host)
            elif isinstance(ip, str):
                self.nodes.add(ip)
            else:
                raise Exception('Unsupported connection object type')

    @abstractmethod
    def _make_group(self: GROUP_SELF, ips: Iterable[Union[str, GROUP_SELF]]) -> GROUP_SELF:
        pass

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        if not isinstance(other, self.__class__):
            return False

        return self.nodes == other.nodes

    def __ne__(self, other: object) -> bool:
        return not self == other

    def run(self, command: str,
            warn: bool = False, hide: bool = True,
            env: Dict[str, str] = None, timeout: int = None,
            callback: Callback = None) -> GROUP_RUN_TYPE:
        caller: Optional[Dict[str, object]] = None
        if not hide:
            # fetching of the caller info should be at the earliest point
            caller = log.caller_info(self.cluster.log)
        return self._run("run", command, caller,
                         warn=warn, hide=hide, env=env, timeout=timeout, callback=callback)

    def sudo(self, command: str,
             warn: bool = False, hide: bool = True,
             env: Dict[str, str] = None, timeout: int = None,
             callback: Callback = None) -> GROUP_RUN_TYPE:
        caller: Optional[Dict[str, object]] = None
        if not hide:
            # fetching of the caller info should be at the earliest point
            caller = log.caller_info(self.cluster.log)
        return self._run("sudo", command, caller,
                         warn=warn, hide=hide, env=env, timeout=timeout, callback=callback)

    @abstractmethod
    def _run(self, do_type: str, command: str, caller: Optional[Dict[str, object]],
             **kwargs: Any) -> GROUP_RUN_TYPE:
        pass

    @abstractmethod
    def get(self, remote_file: str, local_file: str) -> None:
        pass

    def put(self, local_file: Union[io.StringIO, str], remote_file: str,
            backup: bool = False, sudo: bool = False,
            mkdir: bool = False, immutable: bool = False) -> None:
        if isinstance(local_file, io.StringIO):
            self.cluster.log.verbose("Text is being transferred to remote file \"%s\" on nodes %s"
                                     % (remote_file, list(self.nodes)))
            # This is a W/A to avoid https://github.com/paramiko/paramiko/issues/1133
            # if text contains non-ASCII characters.
            # Use the same encoding as paramiko uses, see paramiko/file.py/BufferedFile.write()

            local_stream: Union[io.BytesIO, str] = io.BytesIO(local_file.getvalue().encode('utf-8'))
            group_to_upload = self
        else:
            if not os.path.isfile(local_file):
                raise Exception(f"File {local_file} does not exist")

            self.cluster.log.verbose("Local file \"%s\" is being transferred to remote file \"%s\" on nodes %s"
                                     % (local_file, remote_file, list(self.nodes)))

            self.cluster.log.verbose('File size: %s' % os.path.getsize(local_file))
            eager_group = self.cluster.make_group(self.nodes)
            local_file_hash = eager_group.get_local_file_sha1(local_file)
            self.cluster.log.verbose('Local file hash: %s' % local_file_hash)
            remote_file_hashes = eager_group.get_remote_file_sha1(remote_file)
            self.cluster.log.verbose('Remote file hashes: %s' % remote_file_hashes)

            hosts_to_upload = []
            for remote_ip, remote_file_hash in remote_file_hashes.items():
                if remote_file_hash != local_file_hash:
                    self.cluster.log.verbose('Local and remote hashes does not match on node \'%s\' %s %s'
                                             % (remote_ip, local_file_hash, remote_file_hash))
                    hosts_to_upload.append(remote_ip)
            if not hosts_to_upload:
                self.cluster.log.verbose('Local and remote hashes are equal on all nodes, no transmission required')
                return

            local_stream = local_file
            group_to_upload = self._make_group(hosts_to_upload)

        group_to_upload._put_with_mv(local_stream, remote_file,
                                     backup=backup, sudo=sudo, mkdir=mkdir, immutable=immutable)

    def _put_with_mv(self, local_stream: Union[io.BytesIO, str], remote_file: str,
                     backup: bool, sudo: bool, mkdir: bool, immutable: bool) -> None:

        if sudo:
            self.cluster.log.verbose('A sudoer upload required')

        if backup:
            self.cluster.log.verbose('File \"%s\" backup required' % remote_file)

        if mkdir:
            self.cluster.log.verbose('A parent directory will be created')

        if immutable:
            self.cluster.log.verbose('File \"%s\" immutable set required' % remote_file)

        advanced_move_required = sudo or backup or immutable or mkdir
        temp_filepath = remote_file

        if advanced_move_required:
            # for unknown reason fabric v2 can't put as sudo, and we should use WA via mv
            # also, if we need to backup the file first, then we also have to upload file to tmp first

            temp_filepath = "/tmp/%s" % uuid.uuid4().hex
            self.cluster.log.verbose("Uploading to temporary file '%s'..." % temp_filepath)

        self._put(local_stream, temp_filepath)

        if not advanced_move_required:
            return

        self.cluster.log.verbose("Moving temporary file '%s' to '%s'..." % (temp_filepath, remote_file))

        # -Z option is necessary for RHEL family to set SELinux context to default type.
        if sudo:
            mv_command = "sudo chown root:root %s && sudo mv -fZ %s %s" % (temp_filepath, temp_filepath, remote_file)
        else:
            mv_command = "mv -fZ %s %s" % (temp_filepath, remote_file)

        if backup:
            if sudo:
                mv_command = "sudo cp -f %s %s.bak$(sudo ls %s* | sudo wc -l); %s" \
                             % (remote_file, remote_file, remote_file, mv_command)
            else:
                mv_command = "cp -f %s %s.bak$(ls %s* | wc -l); %s" \
                             % (remote_file, remote_file, remote_file, mv_command)

        if mkdir:
            file_directory = "/".join(remote_file.split('/')[:-1])
            if sudo:
                mv_command = f"sudo mkdir -p {file_directory}; {mv_command}"
            else:
                mv_command = f"mkdir -p {file_directory}; {mv_command}"

        mv_command = "cmp --silent %s %s || (%s)" % (remote_file, temp_filepath, mv_command)

        if immutable:
            if sudo:
                mv_command = "sudo chattr -i %s; %s; sudo chattr +i %s" % (remote_file, mv_command, remote_file)
            else:
                mv_command = "chattr -i %s; %s; chattr +i %s" % (remote_file, mv_command, remote_file)

        self.sudo(mv_command)

    @abstractmethod
    def _put(self, local_stream: Union[io.BytesIO, str], remote_file: str) -> None:
        pass

    def _unsafe_make_runners_result(self, host_results: HostToResult) -> RunnersGroupResult:
        return RunnersGroupResult(self.cluster,
                                  {host: cast(RunnersResult, result) for host, result in host_results.items()})

    def call(self, action: Callable[..., _T], **kwargs: object) -> _T:
        func = cast(FunctionType, action)
        callable_path = "%s.%s" % (func.__module__, func.__name__)
        self.cluster.log.debug("Running %s: " % callable_path)
        result = action(self, **kwargs)
        if result is not None:
            self.cluster.log.debug(result)

        return result

    def call_batch(self: GROUP_SELF, actions: List[Callable[[GROUP_SELF], Any]]) -> None:
        for action in actions:
            self.call(action)

    def get_online_nodes(self: GROUP_SELF, online: bool) -> GROUP_SELF:
        online_hosts = [host for host, node_context in self.cluster.context['nodes'].items()
                        if node_context['access']['online'] == online]
        return self._make_group(online_hosts).intersection_group(self)

    def get_accessible_nodes(self: GROUP_SELF) -> GROUP_SELF:
        accessible = [host for host, node_context in self.cluster.context['nodes'].items()
                      if node_context['access']['accessible']]
        return self._make_group(accessible).intersection_group(self)

    def get_sudo_nodes(self: GROUP_SELF) -> GROUP_SELF:
        sudo = [host for host, node_context in self.cluster.context['nodes'].items()
                if node_context['access']['sudo'] != "No"]
        return self._make_group(sudo).intersection_group(self)

    def get_ordered_members_list(self: GROUP_SELF, apply_filter: GroupFilter = None) -> List[GROUP_SELF]:
        nodes = self.get_ordered_members_configs_list(apply_filter)
        return [self._make_group([node['connect_to']]) for node in nodes]

    def get_ordered_members_configs_list(self, apply_filter: GroupFilter = None) -> List[NodeConfig]:

        result = []
        # we have to iterate strictly in order which was defined by user in config-file
        for node in self.cluster.inventory['nodes']:
            # is iterable node from inventory is part of current NodeGroup?
            if node['connect_to'] in self.nodes:

                # apply filters
                suitable = True
                if apply_filter is not None:
                    if callable(apply_filter):
                        if not apply_filter(node):
                            suitable = False
                    else:
                        # here intentionally there is no way to filter by values in lists field,
                        # for this you need to use custom functions.
                        # Current solution implemented in this way because the filtering strategy is
                        # unclear - do I need to include when everything matches or is partial matching enough?
                        for key, value in apply_filter.items():
                            if node.get(key) is None:
                                suitable = False
                                break
                            if isinstance(value, list):
                                if node[key] not in value:
                                    suitable = False
                                    break
                            # elif should definitely be here, not if
                            elif node[key] != value:
                                suitable = False
                                break

                # if not filtered
                if suitable:
                    result.append(node)

        return result

    def get_first_member(self: GROUP_SELF, apply_filter: GroupFilter = None) -> GROUP_SELF:
        results = self.get_ordered_members_list(apply_filter)
        if not results:
            raise Exception("Failed to find first group member by the given criteria")
        return results[0]

    def get_any_member(self: GROUP_SELF, apply_filter: GroupFilter = None) -> GROUP_SELF:
        member: GROUP_SELF = random.choice(self.get_ordered_members_list(apply_filter))
        self.cluster.log.verbose(f'Selected node {member.get_host()}')
        return member

    def get_member_by_name(self: GROUP_SELF, name: str) -> GROUP_SELF:
        return self.get_first_member({"name": name})

    def new_group(self: GROUP_SELF, apply_filter: GroupFilter = None) -> GROUP_SELF:
        return self._make_group(self.get_ordered_members_list(apply_filter))

    def include_group(self: GROUP_SELF, group: GROUP_SELF) -> GROUP_SELF:
        ips = self.nodes.union(group.nodes)
        return self._make_group(ips)

    def exclude_group(self: GROUP_SELF, group: GROUP_SELF) -> GROUP_SELF:
        ips = self.nodes - group.nodes
        return self._make_group(ips)

    def intersection_group(self: GROUP_SELF, group: GROUP_SELF) -> GROUP_SELF:
        ips = self.nodes.intersection(group.nodes)
        return self._make_group(ips)

    def get_nodes_names(self) -> List[str]:
        result = []
        members = self.get_ordered_members_configs_list()
        for node in members:
            result.append(node['name'])
        return result

    def get_node_name(self) -> str:
        if len(self.nodes) != 1:
            raise Exception("Cannot get the only name from not a single node")

        return self.get_nodes_names()[0]

    def get_hosts(self) -> List[str]:
        members = self.get_ordered_members_list()
        return [node.get_host() for node in members]

    def get_host(self) -> str:
        if len(self.nodes) != 1:
            raise Exception("Cannot get the only host from not a single node")

        return next(iter(self.nodes))

    def get_config(self) -> NodeConfig:
        if len(self.nodes) != 1:
            raise Exception("Cannot get the only node config from not a single node")

        return self.get_ordered_members_configs_list()[0]

    def is_empty(self) -> bool:
        return not self.nodes

    def has_node(self, node_name: str) -> bool:
        return node_name in self.get_nodes_names()

    def get_new_nodes(self: GROUP_SELF) -> GROUP_SELF:
        return self.new_group(lambda node: 'add_node' in node['roles'])

    def get_new_nodes_or_self(self: GROUP_SELF) -> GROUP_SELF:
        new_nodes = self.get_new_nodes()
        if not new_nodes.is_empty():
            return new_nodes
        return self

    def get_nodes_for_removal(self: GROUP_SELF) -> GROUP_SELF:
        return self.new_group(lambda node: 'remove_node' in node['roles'])

    def get_changed_nodes(self: GROUP_SELF) -> GROUP_SELF:
        return self.get_new_nodes().include_group(self.get_nodes_for_removal())

    def get_unchanged_nodes(self: GROUP_SELF) -> GROUP_SELF:
        return self.exclude_group(self.get_changed_nodes())

    def get_final_nodes(self: GROUP_SELF) -> GROUP_SELF:
        return self.new_group(lambda node: 'remove_node' not in node['roles'])

    def get_initial_nodes(self: GROUP_SELF) -> GROUP_SELF:
        return self.new_group(lambda node: 'add_node' not in node['roles'])

    def nodes_amount(self) -> int:
        """
        Returns the number of nodes within a group
        :return: Integer
        """
        return len(self.nodes)

    def get_nodes_os(self) -> str:
        """
        Returns the detected operating system family for group.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "rhel9", "multiple", "unknown", "unsupported".
        """
        return self.cluster.get_os_family_for_nodes(self.nodes)

    def is_multi_os(self) -> bool:
        """
        Returns true if same group contains nodes with multiple OS families
        :return: Boolean
        """
        return self.get_nodes_os() == 'multiple'

    def get_subgroup_with_os(self: GROUP_SELF, os_family: str) -> GROUP_SELF:
        """
        Forms and returns a new group from the nodes of the original group that have a specific OS family
        :param os_family: The name of required OS family
        :return: NodeGroup
        """
        if os_family not in ['debian', 'rhel', 'rhel8', 'rhel9']:
            raise Exception('Unsupported OS family provided')
        hosts = []
        for host in self.nodes:
            node_os_family = self.cluster.get_os_family_for_node(host)
            if node_os_family == os_family:
                hosts.append(host)
        return self._make_group(hosts)


class NodeGroup(AbstractGroup[RunnersGroupResult]):
    def _make_group(self: NodeGroup, ips: Iterable[Union[str, NodeGroup]]) -> NodeGroup:
        return NodeGroup(ips, self.cluster)

    def _make_defer(self, executor: RemoteExecutor) -> DeferredGroup:
        return DeferredGroup(self.nodes, self.cluster, executor)

    def new_defer(self, timeout: int = None) -> DeferredGroup:
        return self.new_executor(timeout).group

    def new_executor(self, timeout: int = None) -> RemoteExecutor:
        return RemoteExecutor(self, timeout=timeout)

    def get(self, remote_file: str, local_file: str) -> None:
        self._do_exec("get", remote_file, local_file)

    def _put(self, local_stream: Union[io.BytesIO, str], remote_file: str) -> None:
        self._do_exec("put", local_stream, remote_file)

    def _run(self, do_type: str, command: str, caller: Optional[Dict[str, object]],
             **kwargs: Any) -> RunnersGroupResult:
        """
        The method should be called directly from run & sudo without any extra wrappers.
        """
        do_stream = not kwargs['hide']
        if do_stream and len(self.nodes) > 1:
            raise ValueError("Streaming of output is supported only for the single node")

        if do_stream and caller is not None:
            logger = self.cluster.log
            kwargs['out_stream'] = log.LoggerWriter(logger, caller, '\t')
            kwargs['err_stream'] = log.LoggerWriter(logger, caller, '\t')

        results = self._do_exec(do_type, command, **kwargs)
        return self._unsafe_make_runners_result(results)

    def _do_exec(self, do_type: str, *args: object, **kwargs: Any) -> HostToResult:
        callback: Callback = kwargs.pop('callback', None)

        executor = RawExecutor(self.cluster, timeout=kwargs.get('timeout'))
        executor.queue(self.get_hosts(), (do_type, args, kwargs), callback=callback)
        executor.flush()

        results = {host: next(iter(results.values()))
                   for host, results in executor.get_last_results().items()}

        if any(isinstance(result, Exception) for result in results.values()):
            raise GroupResultException(NodeGroupResult(self.cluster, results))

        return results

    def wait_for_reboot(self, initial_boot_history: RunnersGroupResult, timeout: int = None) -> RunnersGroupResult:
        results = self._await_rebooted_nodes(timeout, initial_boot_history=initial_boot_history)
        if any(isinstance(result, Exception) or result == initial_boot_history.get(host)
               for host, result in results.items()):
            raise GroupResultException(NodeGroupResult(self.cluster, results))

        return self._unsafe_make_runners_result(results)

    def wait_and_get_boot_history(self, timeout: int = None) -> RunnersGroupResult:
        return self.wait_for_reboot(RunnersGroupResult(self.cluster, {}), timeout=timeout)

    def _await_rebooted_nodes(self, timeout: int = None, initial_boot_history: RunnersGroupResult = None) \
            -> HostToResult:

        executor = RawExecutor(self.cluster)
        return executor.wait_for_boot(self.get_hosts(), timeout, initial_boot_history)

    def get_local_file_sha1(self, filename: str) -> str:
        return utils.get_local_file_sha1(filename)

    def get_remote_file_sha1(self, filename: str) -> Dict[str, Optional[str]]:
        results = self.sudo("openssl sha1 %s" % filename, warn=True)
        return {host: result.stdout.split("= ")[1].strip() if result.stdout else None
                for host, result in results.items()}


class DeferredGroup(AbstractGroup[Token]):
    def __init__(self, ips: Iterable[Union[str, DeferredGroup]], cluster: object, executor: RemoteExecutor):
        super().__init__(ips, cluster)
        self._executor = executor

    @property
    def executor(self) -> RemoteExecutor:
        return self._executor

    def flush(self) -> None:
        self._executor.flush()

    def _make_group(self, ips: Iterable[Union[str, DeferredGroup]]) -> DeferredGroup:
        return DeferredGroup(ips, self.cluster, self._executor)

    def get(self, remote_file: str, local_file: str) -> None:
        self._do_queue("get", remote_file, local_file)

    def _run(self, do_type: str, command: str, caller: Optional[Dict[str, object]], **kwargs: object) -> Token:
        do_stream = not kwargs['hide']
        if do_stream:
            # To support streaming of output with use of RemoteExecutor in deferred mode, it is necessary to:
            # 1) Make sure that no two commands are executed with streaming in parallel to avoid mess in output
            # 2) Do not print output twice if error occurred.
            raise ValueError("Streaming of output is currently not supported in deferred mode")
        return self._do_queue(do_type, command, **kwargs)

    def _put(self, local_stream: Union[io.BytesIO, str], remote_file: str) -> None:
        self._do_queue("put", local_stream, remote_file)

    def _do_queue(self, do_type: str, *args: object, **kwargs: Any) -> Token:
        callback: Callback = kwargs.pop('callback', None)
        return self._executor.queue(self.get_hosts(), (do_type, args, kwargs), callback=callback)

    def include_group(self: DeferredGroup, group: DeferredGroup) -> DeferredGroup:
        self._check_same_bound_executor(group)
        return AbstractGroup.include_group(self, group)

    def exclude_group(self, group: DeferredGroup) -> DeferredGroup:
        self._check_same_bound_executor(group)
        return AbstractGroup.exclude_group(self, group)

    def intersection_group(self, group: DeferredGroup) -> DeferredGroup:
        self._check_same_bound_executor(group)
        return AbstractGroup.intersection_group(self, group)

    def _check_same_bound_executor(self, group: DeferredGroup) -> None:
        if self._executor is not group._executor:
            raise ValueError("Trying to apply set operation on deferred groups bound to different executors")


class RemoteExecutor(RawExecutor):
    def __init__(self, group: NodeGroup, connection_pool: ConnectionPool = None, timeout: int = None) -> None:
        super().__init__(group.cluster, connection_pool, timeout)
        self.group: DeferredGroup = group._make_defer(self)
        self.cluster = group.cluster

    def flush(self) -> None:
        """
        Flushes the connections' queue.
        Throws GroupException in case of any failure.

        :return: grouped tokenized results per connection.
        """
        super().flush()

        for host, results in self._last_results.items():
            if any(isinstance(result, Exception) for _, result in results.items()):
                raise RemoteGroupException(self.cluster, self._last_results)


class GroupException(Exception):
    def __init__(self, cluster: object, results: Dict[str, List[GenericResult]]):
        self.cluster = cluster
        self.results = results

    def _make_group(self, hosts: Iterable[str]) -> NodeGroup:
        return NodeGroup(hosts, self.cluster)

    def is_any_excepted(self) -> bool:
        """
        Returns true if at least one result in group is an exception

        :return: Boolean
        """
        return len(self.get_excepted_hosts_list()) > 0

    def get_excepted_hosts_list(self) -> List[str]:
        """
        Returns a list of hosts, for which the result is an exception.

        :return: List with hosts
        """
        excepted_hosts: List[str] = []
        for host, results in self.results.items():
            if any(isinstance(result, Exception) for result in results):
                excepted_hosts.append(host)
        return excepted_hosts

    def get_excepted_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is an exception.

        :return: NodeGroup:
        """
        nodes_list = self.get_excepted_hosts_list()
        return self._make_group(nodes_list)

    def get_exited_hosts_list(self) -> List[str]:
        """
        Returns a list of hosts, for which the result is the completion of all commands.

        :return: List with hosts
        """
        exited_hosts: List[str] = []
        for host, results in self.results.items():
            if all(isinstance(result, RunnersResult) for result in results):
                exited_hosts.append(host)
        return exited_hosts

    def get_exited_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is the completion of all commands.

        :return: NodeGroup
        """
        nodes_list = self.get_exited_hosts_list()
        return self._make_group(nodes_list)

    def __str__(self) -> str:
        # We always print output of all commands in the batch even if they are not failed,
        # for the reason that the user code might want to print output of some commands in the batch,
        # but failed to do that because of the exception.
        host_outputs = []
        for host, results in self.results.items():
            output = f"{host}:"

            # filter out transfer results and the last exception if present
            runners_results = [res for res in results if isinstance(res, RunnersResult)]
            if runners_results:
                merged_result = RunnersResult.merge(runners_results)
                output += f" code={merged_result.repr_code()}"
                repr_out = merged_result.repr_out(hide_already_printed=True)
                if repr_out:
                    output += '\n\t' + repr_out.replace('\n', '\n\t')

            # The exception may be only the last in the list. We are also sure to have at least one result per node.
            if isinstance(results[-1], Exception):
                exception = errors.wrap_kme_exception(results[-1])
                output += '\n\t' + str(exception).replace('\n', '\n\t')

            host_outputs.append(output)

        return "\n".join(host_outputs)


class GroupResultException(GroupException):
    def __init__(self, result: GenericGroupResult[GenericResult]):
        super().__init__(result.cluster, {host: [res] for host, res in result.items()})
        self.result = result


class RemoteGroupException(GroupException):
    def __init__(self, cluster: object, results: Dict[str, TokenizedResult]):
        super().__init__(cluster, {host: list(res.values()) for host, res in results.items()})
