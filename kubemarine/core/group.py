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
import re
import time
import uuid
from datetime import datetime
from typing import Callable, Dict, List, Union, Any, TypeVar, Mapping, Iterator, cast, Optional, Iterable

import invoke
from invoke import UnexpectedExit

from kubemarine.core import utils, log
from kubemarine.core.executor import (
    RemoteExecutor, Token, GenericResult, RunnersResult,
    get_active_executor, HostToResult
)

NodeConfig = Dict[str, Any]
GroupFilter = Union[Callable[[NodeConfig], bool], NodeConfig]

_Result = TypeVar('_Result', bound=GenericResult, covariant=True)


class GenericGroupResult(Mapping[str, _Result]):

    def __init__(self, cluster, results: Mapping[str, _Result]) -> None:
        self.cluster = cluster
        self._result: Dict[str, _Result] = dict(results)

    def __getitem__(self, host: str) -> _Result:
        return self._result[host]

    def __len__(self) -> int:
        return len(self._result)

    def __iter__(self) -> Iterator[str]:
        return iter(self._result)

    @property
    def succeeded(self):
        return dict(item for item in self.items()
                    if not isinstance(item[1], Exception))

    @property
    def failed(self):
        return dict(item for item in self.items()
                    if isinstance(item[1], Exception))

    def get_simple_out(self) -> str:
        if len(self) != 1:
            raise NotImplementedError("Simple output can be returned only for NodeGroupResult consisted of "
                                      "exactly one node, but %s were provided." % list(self.keys()))

        res = list(self.values())[0]
        if not isinstance(res, RunnersResult):
            raise NotImplementedError("It does not make sense to return simple output for result of type %s"
                                      % type(res))

        return res.stdout

    def __str__(self) -> str:
        output = ""
        for host, result in self.items():

            # TODO: support print other possible exceptions
            if isinstance(result, invoke.exceptions.UnexpectedExit):
                result = result.result

            # for now, we do not know how-to print transfer result
            if not isinstance(result, RunnersResult):
                continue

            if output != "":
                output += "\n"
            output += "\t%s: code=%i" % (host, result.exited)
            if result.stdout:
                output += "\n\t\tSTDOUT: %s" % result.stdout.replace("\n", "\n\t\t        ")
            if result.stderr:
                output += "\n\t\tSTDERR: %s" % result.stderr.replace("\n", "\n\t\t        ")
        return output

    def get_group(self) -> NodeGroup:
        """
        Forms and returns a new group from node results
        :return: NodeGroup
        """
        return self.cluster.make_group(self.keys())

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

    def is_any_excepted(self) -> bool:
        """
        Returns true if at least one result in group is an exception
        :return: Boolean
        """
        return len(self.get_excepted_hosts_list()) > 0

    def is_any_failed(self) -> bool:
        """
        Returns true if at least one result in the group finished with non-zero code
        :return: Boolean
        """
        return len(self.get_failed_hosts_list()) > 0

    def get_excepted_hosts_list(self) -> List[str]:
        """
        Returns a list of hosts, for which the result is an exception
        :return: List with hosts
        """
        failed_hosts: List[str] = []
        for host, result in self.items():
            if isinstance(result, Exception):
                failed_hosts.append(host)
        return failed_hosts

    def get_excepted_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is an exception
        :return: NodeGroup:
        """
        nodes_list = self.get_excepted_hosts_list()
        return self.cluster.make_group(nodes_list)

    def get_exited_hosts_list(self) -> List[str]:
        """
        Returns a list of hosts, for which the result is the completion of the command and the formation of
        the RunnersResult
        :return: List with hosts
        """
        failed_hosts: List[str] = []
        for host, result in self.items():
            if isinstance(result, RunnersResult):
                failed_hosts.append(host)
        return failed_hosts

    def get_exited_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is the completion of the command and the
        formation of the Fabric Result
        :return: NodeGroup:
        """
        nodes_list = self.get_exited_hosts_list()
        return self.cluster.make_group(nodes_list)

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
        return self.cluster.make_group(nodes_list)

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
        return self.cluster.make_group(nodes_list)

    def get_nodes_group_where_value_in_stderr(self, value: str) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: NodeGroup
        """
        nodes_list = self.get_hosts_list_where_value_in_stderr(value)
        return self.cluster.make_group(nodes_list)

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

    def __eq__(self, other) -> bool:
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

    def __ne__(self, other) -> bool:
        return not self == other


class NodeGroupResult(GenericGroupResult[GenericResult]):
    pass


class RunnersGroupResult(GenericGroupResult[RunnersResult]):
    pass


class GroupException(Exception):
    def __init__(self, result: GenericGroupResult[GenericResult]):
        self.result: GenericGroupResult[GenericResult] = result


class NodeGroup:

    def __init__(self, hosts: Iterable[str], cluster):
        from kubemarine.core.cluster import KubernetesCluster

        self.cluster: KubernetesCluster = cluster
        self.nodes = set(hosts)

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True

        if not isinstance(other, NodeGroup):
            return False

        return self.nodes == other.nodes

    def __ne__(self, other: object) -> bool:
        return not self == other

    def _make_runners_result(self, result: NodeGroupResult) -> RunnersGroupResult:
        return RunnersGroupResult(self.cluster,
                                  {host: cast(RunnersResult, res) for host, res in result.items()})

    def _make_result_or_fail(self, results: HostToResult) -> NodeGroupResult:
        group_result = NodeGroupResult(self.cluster, results)

        if group_result.is_any_excepted():
            raise GroupException(group_result)

        return group_result

    def run(self, command: str,
            warn: bool = False, hide: bool = True,
            env: Dict[str, str] = None, timeout: int = None,
            logging_stream: bool = False) -> RunnersGroupResult:
        caller: Optional[Dict[str, object]] = None
        if logging_stream:
            # fetching of the caller info should be at the earliest point
            caller = log.caller_info(self.cluster.log)
        return self._do("run", command, caller,
                        warn=warn, hide=hide, env=env, timeout=timeout)

    def sudo(self, command: str,
             warn: bool = False, hide: bool = True,
             env: Dict[str, str] = None, timeout: int = None,
             logging_stream: bool = False) -> RunnersGroupResult:
        caller: Optional[Dict[str, object]] = None
        if logging_stream:
            # fetching of the caller info should be at the earliest point
            caller = log.caller_info(self.cluster.log)
        return self._do("sudo", command, caller,
                        warn=warn, hide=hide, env=env, timeout=timeout)

    def get(self, remote_file: str, local_file: str) -> None:
        self._do_with_wa("get", remote_file, local_file)

    def put(self, local_file: Union[io.StringIO, str], remote_file: str,
            backup=False, sudo=False, mkdir=False, immutable=False) -> None:
        self._put(local_file, remote_file, False,
                  backup=backup, sudo=sudo, mkdir=mkdir, immutable=immutable)

    def defer(self) -> DeferredGroup:
        return DeferredGroup(self)

    def _put(self, local_file: Union[io.StringIO, str], remote_file: str,
             deferred: bool, **kwargs) -> None:
        if isinstance(local_file, io.StringIO):
            self.cluster.log.verbose("Text is being transferred to remote file \"%s\" on nodes %s with options %s"
                                     % (remote_file, list(self.nodes), kwargs))
            # This is a W/A to avoid https://github.com/paramiko/paramiko/issues/1133
            # if text contains non-ASCII characters.
            # Use the same encoding as paramiko uses, see paramiko/file.py/BufferedFile.write()
            bytes_stream = io.BytesIO(local_file.getvalue().encode('utf-8'))
            self._advanced_put(bytes_stream, remote_file, deferred, **kwargs)
            return

        self.cluster.log.verbose("Local file \"%s\" is being transferred to remote file \"%s\" on nodes %s with options %s"
                                 % (local_file, remote_file, list(self.nodes), kwargs))

        self.cluster.log.verbose('File size: %s' % os.path.getsize(local_file))
        local_file_hash = self.get_local_file_sha1(local_file)
        self.cluster.log.verbose('Local file hash: %s' % local_file_hash)
        remote_file_hashes = self.get_remote_file_sha1(remote_file)
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

        group_to_upload = self.cluster.make_group(hosts_to_upload)

        if not os.path.isfile(local_file):
            raise Exception(f"File {local_file} does not exist")

        group_to_upload._advanced_put(local_file, remote_file, deferred, **kwargs)

    def _advanced_put(self, local_stream: Union[io.BytesIO, str], remote_file: str, deferred: bool,
                      backup=False, sudo=False, mkdir=False, immutable=False) -> None:

        if sudo:
            self.cluster.log.verbose('A sudoer upload required')

        if backup:
            self.cluster.log.verbose('File \"%s\" backup required' % remote_file)

        if mkdir:
            self.cluster.log.verbose('A parent directory will be created')

        if immutable:
            self.cluster.log.verbose('File \"%s\" immutable set required' % remote_file)

        advanced_move_required = sudo or backup or immutable
        temp_filepath = remote_file

        if advanced_move_required:
            # for unknown reason fabric v2 can't put as sudo, and we should use WA via mv
            # also, if we need to backup the file first, then we also have to upload file to tmp first

            temp_filepath = "/tmp/%s" % uuid.uuid4().hex
            self.cluster.log.verbose("Uploading to temporary file '%s'..." % temp_filepath)

        if deferred:
            # TODO why we do not put async in eager mode, but still put async in deferred mode?
            #  See else branch below.
            self._do_queue("put", local_stream, temp_filepath)
        else:
            # for unknown reason fabric v2 can't put async
            self._do_with_wa("put", local_stream, temp_filepath, is_async=False)

        if not advanced_move_required:
            return

        self.cluster.log.verbose("Moving temporary file '%s' to '%s'..." % (temp_filepath, remote_file))

        if sudo:
            mv_command = "sudo chown root:root %s && sudo mv -f %s %s" % (temp_filepath, temp_filepath, remote_file)
        else:
            mv_command = "mv -f %s %s" % (temp_filepath, remote_file)

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

        if deferred:
            self.defer().sudo(mv_command)
        else:
            self.sudo(mv_command)

    def _do(self, do_type: str, command: str, caller: Optional[Dict[str, object]], **kwargs) -> RunnersGroupResult:
        """
        The method should be called directly from run & sudo without any extra wrappers.
        """
        do_stream = not kwargs['hide'] or caller is not None
        if do_stream and len(self.nodes) > 1:
            raise ValueError("Streaming of output is supported only for the single node")

        logger = self.cluster.log
        if caller is not None:
            # We want to stream output immediately to logging framework, thus not hide.
            kwargs['hide'] = False

            out = log.LoggerWriter(logger, caller, '[remote] ')
            err = log.LoggerWriter(logger, caller, '[stderr] ')

            results = self._do_with_wa(do_type, command, out_stream=out, err_stream=err, **kwargs)
        else:
            results = self._do_with_wa(do_type, command, **kwargs)
            # if hide is False, we already logged only to stdout, and should log to other handlers.
            if not kwargs['hide']:
                logger.debug(results, extra={'ignore_stdout': True})

        return self._make_runners_result(results)

    def _do_with_wa(self, do_type, *args, **kwargs) -> NodeGroupResult:
        left_nodes: List[str] = list(self.nodes)
        retry = 0
        results: HostToResult = {}
        while True:
            retry += 1

            result = self._do_exec(left_nodes, do_type, *args, **kwargs)
            results.update(result)
            left_nodes = [host for host, result in results.items() if isinstance(result, Exception)]

            if not left_nodes or retry >= self.cluster.globals['workaround']['retries'] \
                    or not self._try_workaround(results, left_nodes):
                break

            self.cluster.log.verbose('Retrying #%s...' % retry)
            time.sleep(self.cluster.globals['workaround']['delay_period'])

        return self._make_result_or_fail(results)

    def _try_workaround(self, results: HostToResult, failed_nodes: List[str]) -> bool:
        not_booted = []

        for host in failed_nodes:
            exception = results[host]
            if isinstance(exception, UnexpectedExit):
                exception_message = str(exception.result)
            else:
                exception_message = str(exception)

            if self.is_allowed_etcd_exception(exception_message):
                self.cluster.log.verbose("Detected ETCD problem at %s, need retry: %s" % (host, exception_message))
            elif self.is_allowed_kubernetes_exception(exception_message):
                self.cluster.log.verbose("Detected kubernetes problem at %s, need retry: %s" % (host, exception_message))
            elif self.is_allowed_connection_exception(exception_message):
                self.cluster.log.verbose("Detected connection exception at %s, will try to reconnect to node. Exception: %s"
                                         % (host, exception_message))
                not_booted.append(host)
            else:
                self.cluster.log.verbose("Detected unavoidable exception at %s, trying to solve automatically: %s"
                                         % (host, exception_message))
                return False

        # if there are not booted nodes, but we succeeded to wait for at least one is booted, we can continue execution
        if not_booted and self.cluster.make_group(not_booted).wait_and_get_active_nodes().is_empty():
            return False

        return True

    def _default_connection_kwargs(self, do_type: str, kwargs: dict) -> dict:
        if do_type in ["run", "sudo"]:
            # by default fabric will print all output from nodes
            # let's disable this feature if it was not forcibly defined
            if kwargs.get("hide") is None:
                kwargs['hide'] = True

            if kwargs.get("timeout", None) is None:
                kwargs["timeout"] = self.cluster.globals['nodes']['command_execution']['timeout']

        return kwargs

    def _do_exec(self, nodes: List[str], do_type: str, *args: object, is_async: bool = True, **kwargs: object) -> HostToResult:
        kwargs = self._default_connection_kwargs(do_type, kwargs)

        try:
            with RemoteExecutor(self.cluster, parallel=is_async, timeout=kwargs.get("timeout")) as executor:
                executor.queue(nodes, (do_type, args, kwargs))

            result: GenericGroupResult[GenericResult] = executor.get_merged_nodegroup_result()
        except GroupException as exc:
            result = exc.result

        return dict(result.items())

    def _do_queue(self, do_type: str, *args: object, **kwargs: object) -> Token:
        kwargs = self._default_connection_kwargs(do_type, kwargs)
        executor = get_active_executor()
        return executor.queue(self.nodes, (do_type, args, kwargs))

    def call(self, action, **kwargs):
        return self.call_batch([action], **{"%s.%s" % (action.__module__, action.__name__): kwargs})

    def call_batch(self, actions, **kwargs):
        results = {}

        for action in actions:

            callable_path = "%s.%s" % (action.__module__, action.__name__)
            self.cluster.log.debug("Running %s: " % callable_path)

            action_kwargs = {}
            if kwargs.get(callable_path) is not None:
                action_kwargs = kwargs[callable_path]

            results[action] = action(self, **action_kwargs)
            if results[action] is not None:
                self.cluster.log.debug(results[action])

        return results

    def get_online_nodes(self, online: bool) -> NodeGroup:
        online_hosts = [host for host, node_context in self.cluster.context['nodes'].items()
                        if node_context['access']['online'] == online]
        return self.cluster.make_group(online_hosts).intersection_group(self)

    def get_accessible_nodes(self) -> NodeGroup:
        accessible = [host for host, node_context in self.cluster.context['nodes'].items()
                      if node_context['access']['accessible']]
        return self.cluster.make_group(accessible).intersection_group(self)

    def get_sudo_nodes(self) -> NodeGroup:
        sudo = [host for host, node_context in self.cluster.context['nodes'].items()
                if node_context['access']['sudo'] != "No"]
        return self.cluster.make_group(sudo).intersection_group(self)

    def wait_for_reboot(self, initial_boot_history: RunnersGroupResult, timeout=None) -> RunnersGroupResult:
        results = self._make_runners_result(self._make_result_or_fail(
            self._await_rebooted_nodes(timeout, initial_boot_history=initial_boot_history)
        ))
        if any(result == initial_boot_history.get(host) for host, result in results.items()):
            raise GroupException(results)

        return results

    def wait_and_get_boot_history(self, timeout=None) -> RunnersGroupResult:
        return self.wait_for_reboot(RunnersGroupResult(self.cluster, {}), timeout=timeout)

    def wait_and_get_active_nodes(self, timeout=None) -> NodeGroup:
        results = self._await_rebooted_nodes(timeout)
        not_booted = [host for host, result in results.items() if isinstance(result, Exception)]
        return self.exclude_group(self.cluster.make_group(not_booted))

    def _await_rebooted_nodes(self, timeout=None, initial_boot_history: RunnersGroupResult = None) \
            -> HostToResult:

        if timeout is None:
            timeout = int(self.cluster.inventory['globals']['nodes']['boot']['timeout'])

        delay_period = self.cluster.globals['nodes']['boot']['defaults']['delay_period']

        if initial_boot_history:
            self.cluster.log.verbose("Initial boot history:\n%s" % initial_boot_history)
        else:
            initial_boot_history = RunnersGroupResult(self.cluster, {})

        left_nodes: List[str] = list(self.nodes)
        results: HostToResult = {}
        time_start = datetime.now()

        self.cluster.log.verbose("Trying to connect to nodes, timeout is %s seconds..." % timeout)

        # each connection has timeout, so the only we need is to repeat connecting attempts
        # during specified number of seconds
        while True:
            attempt_time_start = datetime.now()
            self.disconnect(left_nodes)

            self.cluster.log.verbose("Attempting to connect to nodes...")
            # this should be invoked without explicit timeout, and relied on fabric Connection timeout instead.
            results.update(self._do_nopasswd(left_nodes, "last reboot"))
            left_nodes = [host for host, result in results.items()
                          if (isinstance(result, Exception)
                              # Something is wrong with sudo access. Node is active.
                              and not NodeGroup.is_require_nopasswd_exception(result))
                          or (not isinstance(result, Exception)
                              and result == initial_boot_history.get(host))]

            waited = (datetime.now() - time_start).total_seconds()

            if not left_nodes or waited >= timeout:
                break

            for host, exc in results.items():
                if isinstance(exc, Exception) and not self.is_allowed_connection_exception(str(exc)):
                    self.cluster.log.verbose("Unexpected exception at %s, node is considered as not booted: %s"
                                             % (host, str(exc)))

            self.cluster.log.verbose("Nodes %s are not ready yet, remaining time to wait %i"
                                     % (left_nodes, timeout - waited))

            attempt_time = (datetime.now() - attempt_time_start).total_seconds()
            if attempt_time < delay_period:
                time.sleep(delay_period - attempt_time)

        if left_nodes:
            self.cluster.log.verbose("Failed to wait for boot of nodes %s" % left_nodes)
        else:
            self.cluster.log.verbose("All nodes are online now")

        return results

    def _do_nopasswd(self, left_nodes: List[str], command: str) -> HostToResult:
        prompt = '[sudo] password: '

        class NoPasswdResponder(invoke.Responder):
            def __init__(self):
                super().__init__(re.escape(prompt), "")

            def submit(self, stream):
                if self.pattern_matches(stream, self.pattern, "index"):
                    # If user appears to be not a NOPASSWD sudoer, "sudo" suggests to write password.
                    # This is a W/A to handle the situation in a docker container without pseudo-TTY (no -t option)
                    # As long as we require NOPASSWD, we can just fail immediately in such cases.
                    raise invoke.exceptions.ResponseNotAccepted("The user should be a NOPASSWD sudoer")

                # The only acceptable situation, responder does nothing.
                return []

        # Currently only NOPASSWD sudoers are supported.
        # Thus, running of connection.sudo("something") should be equal to connection.run("sudo something")
        return self._do_exec(left_nodes, "run", f"sudo -S -p '{prompt}' {command}",
                             is_async=True,
                             watchers=[NoPasswdResponder()])

    @staticmethod
    def is_require_nopasswd_exception(exc: Exception):
        return isinstance(exc, invoke.exceptions.Failure) \
               and isinstance(exc.reason, invoke.exceptions.ResponseNotAccepted)

    def is_allowed_connection_exception(self, exception_message):
        exception_message = exception_message.partition('\n')[0]
        for known_exception_message in self.cluster.globals['connection']['bad_connection_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    def is_allowed_etcd_exception(self, exception_message):
        for known_exception_message in self.cluster.globals['etcd']['temporary_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    def is_allowed_kubernetes_exception(self, exception_message):
        for known_exception_message in self.cluster.globals['kubernetes']['temporary_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    def get_local_file_sha1(self, filename: str) -> str:
        return utils.get_local_file_sha1(filename)

    def get_remote_file_sha1(self, filename: str) -> Dict[str, str]:
        results = self.sudo("openssl sha1 %s" % filename, warn=True)
        return {host: result.stdout.split("= ")[1].strip() if result.stdout else None
                for host, result in results.items()}

    def get_ordered_members_list(self, apply_filter: GroupFilter = None) -> List[NodeGroup]:
        nodes = self.get_ordered_members_configs_list(apply_filter)
        return [self.cluster.make_group([node]) for node in nodes]

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

    def get_first_member(self, apply_filter: GroupFilter = None) -> NodeGroup:
        results = self.get_ordered_members_list(apply_filter=apply_filter)
        if not results:
            raise Exception("Failed to find first group member by the given criteria")
        return results[0]

    def get_any_member(self, apply_filter: GroupFilter = None) -> NodeGroup:
        member: NodeGroup = random.choice(self.get_ordered_members_list(apply_filter=apply_filter))
        self.cluster.log.verbose(f'Selected node {member.get_host()}')
        return member

    def get_member_by_name(self, name) -> NodeGroup:
        return self.get_first_member(apply_filter={"name": name})

    def new_group(self, apply_filter: GroupFilter = None) -> NodeGroup:
        return self.cluster.make_group(self.get_ordered_members_list(apply_filter=apply_filter))

    def include_group(self, group: Optional[NodeGroup]) -> NodeGroup:
        if group is None:
            return self

        ips = self.nodes.union(group.nodes)
        return self.cluster.make_group(ips)

    def exclude_group(self, group: Optional[NodeGroup]) -> NodeGroup:
        if group is None:
            return self

        ips = self.nodes - group.nodes
        return self.cluster.make_group(ips)

    def intersection_group(self, group: Optional[NodeGroup]) -> NodeGroup:
        if group is None:
            return self.cluster.make_group([])

        ips = self.nodes.intersection(group.nodes)
        return self.cluster.make_group(ips)

    def disconnect(self, hosts: List[str] = None):
        for host in self.nodes:
            if host in (hosts or self.nodes):
                self.cluster.log.verbose('Disconnected session with %s' % host)
                cxn = self.cluster.connection_pool.get_connection(host)
                cxn.close()
                cxn._sftp = None

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

    def get_new_nodes(self) -> NodeGroup:
        return self.intersection_group(self.cluster.nodes.get('add_node'))

    def get_new_nodes_or_self(self) -> NodeGroup:
        new_nodes = self.get_new_nodes()
        if not new_nodes.is_empty():
            return new_nodes
        return self

    def get_nodes_for_removal(self) -> NodeGroup:
        return self.intersection_group(self.cluster.nodes.get('remove_node'))

    def get_nodes_for_removal_or_self(self) -> NodeGroup:
        nodes_for_removal = self.get_nodes_for_removal()
        if not nodes_for_removal.is_empty():
            return nodes_for_removal
        return self

    def get_changed_nodes(self) -> NodeGroup:
        return self.get_new_nodes().include_group(self.get_nodes_for_removal())

    def get_unchanged_nodes(self) -> NodeGroup:
        return self.exclude_group(self.get_changed_nodes())

    def get_final_nodes(self) -> NodeGroup:
        return self.exclude_group(self.cluster.nodes.get('remove_node'))

    def get_initial_nodes(self) -> NodeGroup:
        return self.exclude_group(self.cluster.nodes.get('add_node'))

    def nodes_amount(self) -> int:
        """
        Returns the number of nodes within a group
        :return: Integer
        """
        return len(self.nodes)

    def get_nodes_os(self) -> str:
        """
        Returns the detected operating system family for group.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "multiple", "unknown", "unsupported".
        """
        return self.cluster.get_os_family_for_nodes(self.nodes)

    def is_multi_os(self) -> bool:
        """
        Returns true if same group contains nodes with multiple OS families
        :return: Boolean
        """
        return self.get_nodes_os() == 'multiple'

    def get_subgroup_with_os(self, os_family: str) -> NodeGroup:
        """
        Forms and returns a new group from the nodes of the original group that have a specific OS family
        :param os_family: The name of required OS family
        :return: NodeGroup
        """
        if os_family not in ['debian', 'rhel', 'rhel8']:
            raise Exception('Unsupported OS family provided')
        hosts = []
        for host in self.nodes:
            node_os_family = self.cluster.get_os_family_for_node(host)
            if node_os_family == os_family:
                hosts.append(host)
        return self.cluster.make_group(hosts)


class DeferredGroup:
    def __init__(self, group: NodeGroup):
        self._group = group

    def run(self, command: str,
            warn: bool = False, hide: bool = True,
            env: Dict[str, str] = None, timeout: int = None) -> Token:
        return self._group._do_queue("run", command,
                                     warn=warn, hide=hide, env=env, timeout=timeout)

    def sudo(self, command: str,
             warn: bool = False, hide: bool = True,
             env: Dict[str, str] = None, timeout: int = None) -> Token:
        return self._group._do_queue("sudo", command,
                                     warn=warn, hide=hide, env=env, timeout=timeout)

    def get(self, remote_file: str, local_file: str) -> None:
        self._group._do_queue("get", remote_file, local_file)

    def put(self, local_file: Union[io.StringIO, str], remote_file: str,
            backup=False, sudo=False, mkdir=False, immutable=False) -> None:
        self._group._put(local_file, remote_file, True,
                         backup=backup, sudo=sudo, mkdir=mkdir, immutable=immutable)
