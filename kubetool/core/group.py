from __future__ import annotations

import io
import os
import random
import subprocess
import time
import uuid
from datetime import datetime
from typing import Callable, Dict, List, Union, IO

import fabric
import invoke
from invoke import UnexpectedExit

from kubetool.core.connections import Connections
from kubetool.core.executor import RemoteExecutor

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
        self.cluster.log.debug(self)

    def get_group(self) -> NodeGroup:
        hosts = []
        for connection in list(self.keys()):
            hosts.append(connection.host)
        return self.cluster.make_group(hosts)

    def is_any_has_code(self, code) -> bool:
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result) and str(result.exited) == str(code):
                return True
        return False

    def is_any_excepted(self) -> bool:
        for conn, result in self.items():
            if isinstance(result, Exception):
                return True
        return False

    def is_any_failed(self) -> bool:
        return self.is_any_has_code(1) or self.is_any_excepted()

    def get_excepted_nodes_list(self) -> List[fabric.connection.Connection]:
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception):
                failed_nodes.append(conn)
        return failed_nodes

    def get_excepted_nodes_group(self) -> NodeGroup:
        nodes_list = self.get_excepted_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_exited_nodes_list(self) -> List[fabric.connection.Connection]:
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, fabric.runners.Result):
                failed_nodes.append(conn)
        return failed_nodes

    def get_exited_nodes_group(self) -> NodeGroup:
        nodes_list = self.get_exited_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_failed_nodes_list(self) -> List[fabric.connection.Connection]:
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception) or result.exited == 1:
                failed_nodes.append(conn)
        return failed_nodes

    def get_failed_nodes_group(self) -> NodeGroup:
        nodes_list = self.get_failed_nodes_list()
        return self.cluster.make_group(nodes_list)

    def get_nonzero_nodes_list(self) -> List[fabric.connection.Connection]:
        failed_nodes: List[fabric.connection.Connection] = []
        for conn, result in self.items():
            if isinstance(result, Exception) or result.exited != 0:
                failed_nodes.append(conn)
        return failed_nodes

    def get_nonzero_nodes_group(self) -> NodeGroup:
        nodes_list = self.get_nonzero_nodes_list()
        return self.cluster.make_group(nodes_list)

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
                raise NotImplementedError('Currently only instances of fabric.runners.Result can be compared!')

            if result != compared_result:
                return False

        return True

    def __ne__(self, other) -> bool:
        return not self == other


class NodeGroup:

    def __init__(self, connections: Connections, cluster):
        from kubetool.core.cluster import KubernetesCluster

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

    def run(self, *args, **kwargs) -> NodeGroupResult:
        return self.do("run", *args, **kwargs)

    def sudo(self, *args, **kwargs) -> NodeGroupResult:
        return self.do("sudo", *args, **kwargs)

    def put(self, local_file: Union[io.StringIO, str], remote_file: str, **kwargs):
        # pop it early, so that StringIO "put" is not affected by unexpected keyword argument
        binary = kwargs.pop("binary", True) is not False

        if isinstance(local_file, io.StringIO):
            self.cluster.log.verbose("Text is being transferred to remote file \"%s\" on nodes %s with options %s"
                                     % (remote_file, list(self.nodes.keys()), kwargs))
            self._put(local_file, remote_file, **kwargs)
            return

        self.cluster.log.verbose("Local file \"%s\" is being transferred to remote file \"%s\" on nodes %s with options %s"
                                 % (local_file, remote_file, list(self.nodes.keys()), kwargs))

        group_to_upload = self
        # Fabric opens file in 'rb' mode.
        open_mode = "b"

        # hashes checking for text files is currently not supported when deploying from windows
        # because we need to change CRLF -> LF when transferring file
        if not binary and self.cluster.is_deploying_from_windows():
            self.cluster.log.verbose("The file for transferring is marked as text. CRLF -> LF transformation is required")
            # Let's open file in 'rt' mode to automatically make CRLF -> LF transformation.
            open_mode = "t"
        else:
            self.cluster.log.verbose('File size: %s' % os.path.getsize(local_file))
            local_file_hash = self.get_local_file_sha1(local_file)
            self.cluster.log.verbose('Local file hash: %s' % local_file_hash)
            remote_file_hashes = self.get_remote_file_sha1(remote_file)
            self.cluster.log.verbose('Remote file hashes: %s' % remote_file_hashes)

            hosts_to_upload = []
            for remote_ip, remote_file_hash in remote_file_hashes.items():
                if remote_file_hash != local_file_hash:
                    self.cluster.log.verbose('Local and remote hashes does not match on node \'%s\' %s %s' % (remote_ip,
                                             local_file_hash, remote_file_hash))
                    hosts_to_upload.append(remote_ip)
            if not hosts_to_upload:
                self.cluster.log.verbose('Local and remote hashes are equal on all nodes, no transmission required')
                return

            group_to_upload = self.cluster.make_group(hosts_to_upload)

        with open(local_file, "r" + open_mode) as local_stream:
            group_to_upload._put(local_stream, remote_file, **kwargs)

    def _put(self, local_stream: IO, remote_file: str, **kwargs):
        hide = kwargs.pop("hide", True) is True
        sudo = kwargs.pop("sudo", False) is True
        backup = kwargs.pop("backup", False) is True
        immutable = kwargs.pop("immutable", False) is True

        # for unknown reason fabric v2 can't put async
        # Let's remember passed value, which by default is True, and make it False forcibly.
        is_async = kwargs.pop("is_async", True) is not False
        kwargs["is_async"] = False

        if sudo:
            self.cluster.log.verbose('A sudoer upload required')

        if backup:
            self.cluster.log.verbose('File \"%s\" backup required' % remote_file)

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
        if not_booted and self.cluster.make_group(not_booted).wait_active_nodes().is_empty():
            return False

        return True

    def _do(self, do_type: str, nodes: Connections, is_async, *args, **kwargs) -> _HostToResult:

        if do_type in ["run", "sudo"]:
            # by default fabric will print all output from nodes
            # let's disable this feature if it was not forcibly defined
            if kwargs.get("hide") is None:
                kwargs['hide'] = True

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

    def wait_for_reboot(self, initial_boot_history: NodeGroupResult, timeout=None) -> NodeGroupResult:
        results = self._await_rebooted_nodes(timeout, initial_boot_history=initial_boot_history)
        return self._make_result_or_fail(
            results,
            lambda host, result: isinstance(result, Exception) or result == initial_boot_history.get(self.nodes[host])
        )

    def get_online_nodes(self) -> 'NodeGroup':
        online = [host for host, node_context in self.cluster.context['nodes'].items() if node_context.get('online', False)]
        return self.cluster.make_group(online).intersection_group(self)

    def wait_active_nodes(self, timeout=None) -> 'NodeGroup':
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
            results.update(self._do("sudo", left_nodes, True, "last reboot", timeout=delay_period))
            left_nodes = {host: left_nodes[host] for host, result in results.items()
                          if isinstance(result, Exception) or result == initial_boot_history.get(self.nodes[host])}

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
        # TODO: Possibly use fabric instead of subprocess to avoid possible permissions conflicts
        openssl_result = subprocess.check_output("openssl sha1 %s" % filename, shell=True)
        # process output is bytes and we have to decode it to utf-8
        return openssl_result.decode("utf-8").split("= ")[1].strip()

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
        return random.choice(self.get_ordered_members_list(provide_node_configs=provide_node_configs,
                                                           apply_filter=apply_filter))

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
        return len(self.nodes.keys())

    def get_nodes_os(self, suppress_exceptions=False):
        detected_os_family = None
        for node in self.get_new_nodes_or_self().get_ordered_members_list(provide_node_configs=True):
            os_family = self.cluster.context["nodes"][node['connect_to']]["os"]['family']
            if os_family == 'unknown' and not suppress_exceptions:
                raise Exception('OS family is unknown')
            if not detected_os_family:
                detected_os_family = os_family
            elif detected_os_family != os_family:
                detected_os_family = 'multiple'
                if not suppress_exceptions:
                    raise Exception(
                        'OS families differ: detected %s and %s in same cluster' % (detected_os_family, os_family))
        return detected_os_family

    def is_multi_os(self):
        return self.get_nodes_os(suppress_exceptions=True) == 'multiple'

    def get_subgroup_with_os(self, os_family) -> NodeGroup:
        if os_family not in ['debian', 'rhel', 'rhel8']:
            raise Exception('Unsupported OS family provided')
        node_names = []
        for node in self.get_ordered_members_list(provide_node_configs=True):
            node_os_family = self.cluster.get_os_family_for_node(node['connect_to'])
            if node_os_family == os_family:
                node_names.append(node['name'])
        return self.cluster.make_group_from_nodes(node_names)
