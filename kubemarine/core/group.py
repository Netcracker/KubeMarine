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

import hashlib
import io
import os
import random
import re
import time
import uuid
from datetime import datetime
from typing import Callable, Dict, List, Union, IO

import fabric
import invoke
from invoke import UnexpectedExit

from kubemarine.core.connections import Connections
from kubemarine.core.executor import RemoteExecutor

_GenericResult = Union[Exception, fabric.runners.Result, fabric.transfer.Result]
_HostToResult = Dict[str, _GenericResult]


# fabric.runners.Result is not equitable OOB, let it make equitable
def _compare_fabric_results(self: fabric.runners.Result, other) -> bool:
    if not isinstance(other, fabric.runners.Result):
        return False

    # todo should other fields be compared? Or probably custom class should be used to store result.
    return self.exited == other.exited \
        and self.stdout == other.stdout \
        and self.stderr == other.stderr


fabric.runners.Result.__eq__ = _compare_fabric_results
fabric.runners.Result.__ne__ = lambda self, other: not _compare_fabric_results(self, other)


class NodeGroupResult(fabric.group.GroupResult, Dict[fabric.connection.Connection, _GenericResult]):

    def __init__(self, cluster, results: _HostToResult or NodeGroupResult = None) -> None:
        super().__init__()

        self.cluster = cluster

        if results is not None:
            for host, result in results.items():
                if isinstance(results, NodeGroupResult):
                    host = host.host
                connection = cluster.nodes['all'].nodes.get(host)
                if connection is None:
                    raise Exception(f'Host "{host}" was not found in provided cluster object')
                self[connection] = result

    def get_simple_out(self) -> str:
        if len(self) != 1:
            raise NotImplementedError("Simple output can be returned only for NodeGroupResult consisted of "
                                      "exactly one node, but %s were provided." % list(self.keys()))

        res = list(self.values())[0]
        if not isinstance(res, fabric.runners.Result):
            raise NotImplementedError("It does not make sense to return simple output for result of type %s"
                                      % type(res))

        return res.stdout

    def __str__(self) -> str:
        output = ""
        for conn, result in self.items():

            # TODO: support print other possible exceptions
            if isinstance(result, invoke.exceptions.UnexpectedExit):
                result = result.result

            # for now we do not know how-to print transfer result
            if not isinstance(result, fabric.runners.Result):
                continue

            if output != "":
                output += "\n"
            output += "\t%s: code=%i" % (conn.host, result.exited)
            if result.stdout:
                output += "\n\t\tSTDOUT: %s" % result.stdout.replace("\n", "\n\t\t        ")
            if result.stderr:
                output += "\n\t\tSTDERR: %s" % result.stderr.replace("\n", "\n\t\t        ")
        return output

    def print(self) -> None:
        """
        Prints debug message to log with results for each node
        :return: None
        """
        self.cluster.log.debug(self)

    def get_group(self) -> NodeGroup:
        """
        Forms and returns a new group from node results
        :return: NodeGroup
        """
        hosts = []
        for connection in list(self.keys()):
            hosts.append(connection.host)
        return self.cluster.make_group(hosts)

    def is_any_has_code(self, code: int or str) -> bool:
        """
        Returns true if some group result has an exit code equal to the given one. Exceptions and other objects in
        results will be ignored.
        :param code: The code with which the result codes will be compared
        :return: Boolean
        """
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result) and str(result.exited) == str(code):
                return True
        return False

    def is_any_excepted(self) -> bool:
        """
        Returns true if at least one result in group is an execution
        :return: Boolean
        """
        for conn, result in self.items():
            if isinstance(result, Exception):
                return True
        return False

    def is_any_failed(self) -> bool:
        """
        Returns true if at least one result in the group finished with code 1 or failed with an exception
        :return: Boolean
        """
        return self.is_any_has_code(1) or self.is_any_excepted()

    def get_excepted_nodes_list(self) -> List[fabric.connection.Connection]:
        """
        Returns a list of nodes connections, for which the result is an exception
        :return: List with nodes connections
        """
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception):
                failed_nodes.append(conn)
        return failed_nodes

    def get_excepted_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is an exception
        :return: NodeGroup:
        """
        nodes_list = self.get_excepted_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_exited_nodes_list(self) -> List[fabric.connection.Connection]:
        """
        Returns a list of nodes connections, for which the result is the completion of the command and the formation of
        the Fabric Result
        :return: List with nodes connections
        """
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result):
                failed_nodes.append(conn)
        return failed_nodes

    def get_exited_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes, for which the result is the completion of the command and the
        formation of the Fabric Result
        :return: NodeGroup:
        """
        nodes_list = self.get_exited_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_failed_nodes_list(self) -> List[fabric.connection.Connection]:
        """
        Returns a list of nodes connections that either exited with an exception, or the exit code is equals 1
        :return: List with nodes connections
        """
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception) or result.exited == 1:
                failed_nodes.append(conn)
        return failed_nodes

    def get_failed_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that either exited with an exception, or the exit code is equals 1
        :return: NodeGroup:
        """
        nodes_list = self.get_failed_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_nonzero_nodes_list(self) -> List[fabric.connection.Connection]:
        """
        Returns a list of nodes connections that exited with non-zero exit code
        :return: List with nodes connections
        """
        nonzero_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception) or result.exited != 0:
                nonzero_nodes.append(conn)
        return nonzero_nodes

    def get_nonzero_nodes_group(self) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that exited with non-zero exit code
        :return: NodeGroup:
        """
        nodes_list = self.get_nonzero_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_nodes_list_where_value_in_stdout(self, value: str) -> List[fabric.connection.Connection]:
        """
        Returns a list of node connections that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: List with nodes connections
        """
        nodes_with_stderr_value: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result) and value in result.stdout:
                nodes_with_stderr_value.append(conn)
        return nodes_with_stderr_value

    def get_nodes_list_where_value_in_stderr(self, value: str) -> List[fabric.connection.Connection]:
        """
        Returns a list of node connections that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: List with nodes connections
        """
        nodes_with_stderr_value: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result) and value in result.stderr:
                nodes_with_stderr_value.append(conn)
        return nodes_with_stderr_value

    def get_nodes_group_where_value_in_stdout(self, value: str) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that contains the given string value in results stdout.
        :param value: The string value to be found in the nodes results stdout.
        :return: NodeGroup
        """
        nodes_list = self.get_nodes_list_where_value_in_stdout(value)
        return self.cluster.make_group(nodes_list)

    def get_nodes_group_where_value_in_stderr(self, value: str) -> NodeGroup:
        """
        Forms and returns new NodeGroup of nodes that contains the given string value in results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: NodeGroup
        """
        nodes_list = self.get_nodes_list_where_value_in_stderr(value)
        return self.cluster.make_group(nodes_list)

    def stdout_contains(self, value: str) -> bool:
        """
        Checks for the presence of the given string in all results stdout.
        :param value: The string value to be found in the nodes results stdout.
        :return: true if string presented
        """
        return len(self.get_nodes_list_where_value_in_stdout(value)) > 0

    def stderr_contains(self, value: str) -> bool:
        """
        Checks for the presence of the given string in all results stderr.
        :param value: The string value to be found in the nodes results stderr.
        :return: true if string presented
        """
        return len(self.get_nodes_list_where_value_in_stderr(value)) > 0

    def __eq__(self, other) -> bool:
        if self is other:
            return True

        if not isinstance(other, NodeGroupResult):
            return False

        if len(self) != len(other):
            return False

        for conn, result in self.items():
            compared_result = other.get(conn)
            if compared_result is None:
                return False

            if not isinstance(result, fabric.runners.Result) or not isinstance(compared_result, fabric.runners.Result):
                raise NotImplementedError('Currently only instances of fabric.runners.Result can be compared')

            if result != compared_result:
                return False

        return True

    def __ne__(self, other) -> bool:
        return not self == other


class NodeGroup:

    def __init__(self, connections: Connections, cluster):
        from kubemarine.core.cluster import KubernetesCluster

        self.cluster: KubernetesCluster = cluster
        self.nodes = connections

    def __eq__(self, other):
        if self is other:
            return True

        if not isinstance(other, NodeGroup):
            return False

        if self.cluster != other.cluster:
            return False

        if len(self.nodes.keys()) != len(other.nodes.keys()):
            return False

        for host, connection in self.nodes.items():
            other_host_conn = other.nodes.get(host)
            if other_host_conn is None:
                return False
            if other_host_conn != connection:
                return False

        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        # TODO: include cluster object and real connections into hash value
        nodes_addresses = tuple(self.nodes.keys())
        return hash(nodes_addresses)

    def _make_result(self, results: _HostToResult) -> NodeGroupResult:
        group_result = NodeGroupResult(self.cluster, results)
        return group_result

    def _make_result_or_fail(self, results: _HostToResult,
                             failure_criteria: Callable[[str, _GenericResult], bool]) -> NodeGroupResult:
        failed_hosts = [host for host, result in results.items() if failure_criteria(host, result)]
        group_result = self._make_result(results)

        if failed_hosts:
            raise fabric.group.GroupException(group_result)

        return group_result

    def run(self, *args, **kwargs) -> NodeGroupResult or int:
        return self.do("run", *args, **kwargs)

    def sudo(self, *args, **kwargs) -> NodeGroupResult or int:
        return self.do("sudo", *args, **kwargs)

    def put(self, local_file: Union[io.StringIO, str], remote_file: str, **kwargs):
        if isinstance(local_file, io.StringIO):
            self.cluster.log.verbose("Text is being transferred to remote file \"%s\" on nodes %s with options %s"
                                     % (remote_file, list(self.nodes.keys()), kwargs))
            # This is a W/A to avoid https://github.com/paramiko/paramiko/issues/1133
            # if text contains non-ASCII characters.
            # Use the same encoding as paramiko uses, see paramiko/file.py/BufferedFile.write()
            bytes_stream = io.BytesIO(local_file.getvalue().encode('utf-8'))
            self._put(bytes_stream, remote_file, **kwargs)
            return

        self.cluster.log.verbose("Local file \"%s\" is being transferred to remote file \"%s\" on nodes %s with options %s"
                                 % (local_file, remote_file, list(self.nodes.keys()), kwargs))

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

        with open(local_file, "rb") as local_stream:
            group_to_upload._put(local_stream, remote_file, **kwargs)

    def _put(self, local_stream: IO, remote_file: str, **kwargs):
        hide = kwargs.pop("hide", True) is True
        sudo = kwargs.pop("sudo", False) is True
        backup = kwargs.pop("backup", False) is True
        mkdir = kwargs.pop("mkdir", False) is True
        immutable = kwargs.pop("immutable", False) is True

        # for unknown reason fabric v2 can't put async
        # Let's remember passed value, which by default is True, and make it False forcibly.
        is_async = kwargs.pop("is_async", True) is not False
        kwargs["is_async"] = False

        if sudo:
            self.cluster.log.verbose('A sudoer upload required')

        if backup:
            self.cluster.log.verbose('File \"%s\" backup required' % remote_file)

        if mkdir:
            self.cluster.log.verbose('A parent directory will be created')

        if immutable:
            self.cluster.log.verbose('File \"%s\" immutable set required' % remote_file)

        if not sudo and not backup and not immutable:
            # no additional commands execution is required - directly upload file
            self.do("put", local_stream, remote_file, **kwargs)
            return

        # for unknown reason fabric v2 can't put as sudo, and we should use WA via mv
        # also, if we need to backup the file first, then we also have to upload file to tmp first

        temp_filepath = "/tmp/%s" % uuid.uuid4().hex
        self.cluster.log.verbose("Uploading to temporary file '%s'..." % temp_filepath)
        self.do("put", local_stream, temp_filepath, **kwargs)

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

        kwargs["hide"] = hide
        kwargs["is_async"] = is_async
        self.sudo(mv_command, **kwargs)

    def get(self, *args, **kwargs):
        return self.do("get", *args, **kwargs)

    def do(self, do_type, *args, **kwargs) -> NodeGroupResult or int:
        raw_results = self._do_with_wa(do_type, *args, **kwargs)
        if isinstance(raw_results, int):
            return raw_results
        group_results = self._make_result_or_fail(raw_results, lambda host, result: isinstance(result, Exception))

        if not kwargs.get('hide', True):
            self.cluster.log.debug(group_results, extra={'ignore_stdout': True})

        return group_results

    def _do_with_wa(self, do_type, *args, **kwargs) -> _HostToResult or int:
        # by default all code is async, but can be set False forcibly
        is_async = kwargs.pop("is_async", True) is not False

        left_nodes = self.nodes
        retry = 0
        results: _HostToResult = {}
        while True:
            retry += 1

            result = self._do(do_type, left_nodes, is_async, *args, **kwargs)
            if isinstance(result, int):
                return result

            results.update(result)
            left_nodes = {host: left_nodes[host] for host, result in results.items() if isinstance(result, Exception)}

            if not left_nodes or retry >= self.cluster.globals['workaround']['retries'] \
                    or not self._try_workaround(results, left_nodes):
                break

            self.cluster.log.verbose('Retrying #%s...' % retry)
            time.sleep(self.cluster.globals['workaround']['delay_period'])

        return results

    def _try_workaround(self, results: _HostToResult, failed_nodes: Connections) -> bool:
        not_booted = []

        for host in failed_nodes.keys():
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

    def _do(self, do_type: str, nodes: Connections, is_async, *args, **kwargs) -> _HostToResult:

        if do_type in ["run", "sudo"]:
            # by default fabric will print all output from nodes
            # let's disable this feature if it was not forcibly defined
            if kwargs.get("hide") is None:
                kwargs['hide'] = True

            if kwargs.get("timeout", None) is None:
                kwargs["timeout"] = self.cluster.globals['nodes']['command_execution']['timeout']

        execution_timeout = kwargs.get("timeout", None)

        results = {}

        if not nodes:
            self.cluster.log.verbose('No nodes to perform %s %s with options: %s' % (do_type, args, kwargs))
            return results

        self.cluster.log.verbose('Performing %s %s on nodes %s with options: %s' % (do_type, args, list(nodes.keys()), kwargs))

        executor = RemoteExecutor(self.cluster, lazy=False, parallel=is_async, timeout=execution_timeout)
        results = executor.queue(nodes, (do_type, args, kwargs))

        if not isinstance(results, int):
            simplified_results = {}
            for cnx, conn_results in results.items():
                raw_results = list(conn_results.values())
                if len(raw_results) > 1:
                    raise Exception('Unexpected condition: not supported multiple results with non-lazy GRE')
                simplified_results[cnx.host] = raw_results[0]
            return simplified_results

        return results

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

    def get_online_nodes(self, online: bool) -> 'NodeGroup':
        online = [host for host, node_context in self.cluster.context['nodes'].items()
                  if node_context['access']['online'] == online]
        return self.cluster.make_group(online).intersection_group(self)

    def get_accessible_nodes(self) -> 'NodeGroup':
        accessible = [host for host, node_context in self.cluster.context['nodes'].items()
                      if node_context['access']['accessible']]
        return self.cluster.make_group(accessible).intersection_group(self)

    def get_sudo_nodes(self) -> 'NodeGroup':
        sudo = [host for host, node_context in self.cluster.context['nodes'].items()
                if node_context['access']['sudo'] != "No"]
        return self.cluster.make_group(sudo).intersection_group(self)

    def wait_for_reboot(self, initial_boot_history: NodeGroupResult, timeout=None) -> NodeGroupResult:
        results = self._await_rebooted_nodes(timeout, initial_boot_history=initial_boot_history)
        return self._make_result_or_fail(
            results,
            lambda host, result: isinstance(result, Exception) or result == initial_boot_history.get(self.nodes[host])
        )

    def wait_and_get_boot_history(self, timeout=None) -> NodeGroupResult:
        results = self._await_rebooted_nodes(timeout)
        return self._make_result_or_fail(results, lambda _, r: isinstance(r, Exception))

    def wait_and_get_active_nodes(self, timeout=None) -> 'NodeGroup':
        results = self._await_rebooted_nodes(timeout)
        not_booted = [host for host, result in results.items() if isinstance(result, Exception)]
        return self.exclude_group(self.cluster.make_group(not_booted))

    def _await_rebooted_nodes(self, timeout=None, initial_boot_history: NodeGroupResult = None) -> _HostToResult:

        if timeout is None:
            timeout = self.cluster.globals['nodes']['boot']['defaults']['timeout']

        delay_period = self.cluster.globals['nodes']['boot']['defaults']['delay_period']

        if initial_boot_history:
            self.cluster.log.verbose("Initial boot history:\n%s" % initial_boot_history)
        else:
            initial_boot_history = NodeGroupResult(self.cluster)

        left_nodes = self.nodes
        results: _HostToResult = {}
        time_start = datetime.now()

        # each connection has timeout, so the only we need is to repeat connecting attempts
        # during specified number of seconds
        while True:
            attempt_time_start = datetime.now()
            self.disconnect(list(left_nodes.keys()))

            self.cluster.log.verbose("Attempting to connect to nodes...")
            # this should be invoked without explicit timeout, and relied on fabric Connection timeout instead.
            results.update(self._do_nopasswd(left_nodes, "last reboot"))
            left_nodes = {host: left_nodes[host] for host, result in results.items()
                          if (isinstance(result, Exception)
                              # Something is wrong with sudo access. Node is active.
                              and not NodeGroup.is_require_nopasswd_exception(result))
                          or (not isinstance(result, Exception)
                              and result == initial_boot_history.get(self.nodes[host]))}

            waited = (datetime.now() - time_start).total_seconds()

            if not left_nodes or waited >= timeout:
                break

            for host, exc in results.items():
                if isinstance(exc, Exception) and not self.is_allowed_connection_exception(str(exc)):
                    self.cluster.log.verbose("Unexpected exception at %s, node is considered as not booted: %s"
                                             % (host, str(exc)))

            self.cluster.log.verbose("Nodes %s are not ready yet, remaining time to wait %i"
                                     % (list(left_nodes.keys()), timeout - waited))

            attempt_time = (datetime.now() - attempt_time_start).total_seconds()
            if attempt_time < delay_period:
                time.sleep(delay_period - attempt_time)

        if left_nodes:
            self.cluster.log.verbose("Failed to wait for boot of nodes %s." % list(left_nodes.keys()))
        else:
            self.cluster.log.verbose("All nodes are online now")

        return results

    def _do_nopasswd(self, left_nodes: Connections, command: str):
        prompt = '[sudo] password: '

        class NoPasswdResponder(invoke.Responder):
            def __init__(self):
                super().__init__(re.escape(prompt), None)

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
        return self._do("run", left_nodes, True, f"sudo -S -p '{prompt}' {command}",
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

    def get_local_file_sha1(self, filename):
        sha1 = hashlib.sha1()

        # Read local file by chunks of 2^16 bytes (65536) and calculate aggregated SHA1
        with open(filename, 'rb') as f:
            while True:
                data = f.read(2 ** 16)
                if not data:
                    break
                sha1.update(data)

        return sha1.hexdigest()

    def get_remote_file_sha1(self, filename):
        results = self._do_with_wa("sudo", "openssl sha1 %s" % filename, warn=True)
        self._make_result_or_fail(results, lambda h, r: isinstance(r, Exception))

        return {host: result.stdout.split("= ")[1].strip() if result.stdout else None
                for host, result in results.items()}

    def get_ordered_members_list(self, provide_node_configs=False, apply_filter=None) \
            -> List[Union[dict, 'NodeGroup']]:

        if apply_filter is None:
            apply_filter = {}

        result = []
        # we have to iterate strictly in order which was defined by user in config-file
        for node in self.cluster.inventory['nodes']:
            # is iterable node from inventory is part of current NodeGroup?
            if node['connect_to'] in self.nodes.keys():

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
                        # unclear - do I need to include when everything matches or is partial partial matching enough?
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
                    if provide_node_configs:
                        result.append(node)
                    else:
                        result.append(node['connection'])

        return result

    def get_member(self, number, provide_node_configs=False, apply_filter=None):
        results = self.get_ordered_members_list(provide_node_configs=provide_node_configs, apply_filter=apply_filter)

        if not results:
            return None

        return results[number]

    def get_first_member(self, provide_node_configs=False, apply_filter=None):
        return self.get_member(0, provide_node_configs=provide_node_configs, apply_filter=apply_filter)

    def get_last_member(self, provide_node_configs=False, apply_filter=None):
        return self.get_member(-1, provide_node_configs=provide_node_configs, apply_filter=apply_filter)

    def get_any_member(self, provide_node_configs=False, apply_filter=None):
        member = random.choice(self.get_ordered_members_list(provide_node_configs=provide_node_configs,
                                                             apply_filter=apply_filter))
        if isinstance(member, NodeGroup):
            # to avoid "Selected node <kubemarine.core.group.NodeGroup object at 0x7f925625d070>" writing to log,
            # let's get node ip from selected member and pass to it to log
            member_str = str(list(member.nodes.keys())[0])
        else:
            member_str = str(member)
        self.cluster.log.verbose(f'Selected node {member_str}')
        return member

    def get_member_by_name(self, name, provide_node_configs=False):
        return self.get_first_member(provide_node_configs=provide_node_configs, apply_filter={"name": name})

    def new_group(self, apply_filter=None):
        return self.cluster.make_group(self.get_ordered_members_list(apply_filter=apply_filter))

    def include_group(self, group):
        if group is None:
            return self

        ips = list(self.nodes.keys()) + list(group.nodes.keys())
        return self.cluster.make_group(list(dict.fromkeys(ips)))

    def exclude_group(self, group):
        if group is None:
            return self

        ips = list(set(self.nodes.keys()) - set(group.nodes.keys()))
        return self.cluster.make_group(list(dict.fromkeys(ips)))

    def intersection_group(self, group):
        if group is None:
            return self.cluster.make_group([])

        ips = list(set(self.nodes.keys()).intersection(set(group.nodes.keys())))
        return self.cluster.make_group(list(dict.fromkeys(ips)))

    def disconnect(self, hosts: List[str] = None):
        for host, cxn in self.nodes.items():
            if host in (hosts or self.nodes.keys()):
                self.cluster.log.verbose('Disconnected session with %s' % host)
                cxn.close()
                cxn._sftp = None

    def get_nodes_names(self) -> List[str]:
        result = []
        members = self.get_ordered_members_list(provide_node_configs=True)
        for node in members:
            result.append(node['name'])
        return result

    def get_node_name(self) -> str:
        if len(self.nodes) != 1:
            raise Exception("Cannot get the only name from not a single node")

        return self.get_first_member(provide_node_configs=True)['name']

    def get_hosts(self) -> List[str]:
        members = self.get_ordered_members_list(provide_node_configs=True)
        return [node['connect_to'] for node in members]

    def get_host(self):
        if len(self.nodes) != 1:
            raise Exception("Cannot get the only host from not a single node")

        return list(self.nodes.keys())[0]

    def is_empty(self) -> bool:
        return not self.nodes

    def has_node(self, node_name):
        return self.get_first_member(apply_filter={"name": node_name}) is not None

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
        return len(self.nodes.keys())

    def get_nodes_os(self) -> str:
        """
        Returns the detected operating system family for group.

        :return: Detected OS family, possible values: "debian", "rhel", "rhel8", "multiple", "unknown", "unsupported".
        """
        return self.cluster.get_os_family_for_nodes(self.nodes.keys())

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
        node_names = []
        for node in self.get_ordered_members_list(provide_node_configs=True):
            node_os_family = self.cluster.get_os_family_for_node(node['connect_to'])
            if node_os_family == os_family:
                node_names.append(node['name'])
        return self.cluster.make_group_from_nodes(node_names)
