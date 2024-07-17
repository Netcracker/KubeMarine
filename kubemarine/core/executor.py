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
import collections
import concurrent
import io
import random
import re
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from types import TracebackType
from typing import (
    Tuple, List, Dict, Callable, Any, Optional, Union, OrderedDict, TypeVar, Type, Mapping,
    Sequence, Generic, Generator
)

import fabric  # type: ignore[import-untyped]
import fabric.transfer  # type: ignore[import-untyped]

import invoke

from kubemarine.core import log, static, errors, connections
from kubemarine.core.connections import ConnectionPool
from kubemarine.core.environment import Environment

EXIT_CODE_PATTERN = re.compile(r'^\n(\d+)\n')


class RunnersResult:
    def __init__(self, commands: List[str], exit_codes: List[int], stdout: str = "", stderr: str = "",
                 hide: bool = False) -> None:
        self.commands = commands
        self.stdout = stdout
        self.stderr = stderr
        self.exit_codes = exit_codes
        self.hide = hide

    @property
    def command(self) -> str:
        if len(self.commands) > 1:
            raise ValueError("Commands cannot be merged")

        return next(iter(self.commands))

    @property
    def exited(self) -> int:
        if len(self.exit_codes) > 1:
            raise ValueError("Exit codes cannot be merged")

        return next(iter(self.exit_codes))

    @property
    def return_code(self) -> int:
        return self.exited

    @property
    def ok(self) -> bool:
        return all(code == 0 for code in self.exit_codes)

    @property
    def failed(self) -> bool:
        return not self.ok

    def __bool__(self) -> bool:
        return self.ok

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RunnersResult):
            return False

        return self.exited == other.exited \
            and self.stdout == other.stdout \
            and self.stderr == other.stderr

    def __ne__(self, other: object) -> bool:
        return not self == other

    @staticmethod
    def merge(results: List['RunnersResult']) -> 'RunnersResult':
        len_ = len(results)
        if len_ == 0:
            raise ValueError("At least one result should be present")
        elif len_ == 1:
            return results[0]

        hide = results[0].hide
        commands = []
        stdout = ""
        stderr = ""
        exit_codes = []
        for result in results:
            if result.hide != hide:
                raise ValueError("Cannot merge instances of RunnersResult with different 'hide' property")
            commands.extend(result.commands)
            stdout += result.stdout
            stderr += result.stderr
            exit_codes.extend(result.exit_codes)

        return RunnersResult(commands, exit_codes, stdout, stderr, hide=hide)

    def __str__(self) -> str:
        return f"Command exited with status {self.repr_code()}.\n" \
               f"{self.repr_out()}"

    def repr_code(self) -> str:
        unique_codes = set(self.exit_codes)
        return str(self.exit_codes[0]) if len(unique_codes) == 1 else "'undefined'"

    def repr_out(self, *, hide_already_printed: bool = False) -> str:
        ret = []
        for x in ("stdout", "stderr"):
            val: str = getattr(self, x)
            if val:
                val = 'already printed' if hide_already_printed and not self.hide else val.rstrip()
                ret.append(f"=== {x} ===\n"
                           f"{val.rstrip()}\n")
        return "\n".join(ret)

    def grep_returned_nothing(self) -> bool:
        return not self.stdout and not self.stderr and self.exited == 1


class Failure(Exception):
    def __init__(self, result: RunnersResult):
        self.result = result

    def __str__(self) -> str:
        ret = self._header()
        repr_out = self.result.repr_out(hide_already_printed=True)
        if repr_out:
            ret.append(repr_out)

        return "\n".join(ret)

    def _header(self) -> List[str]:
        return []


class CommandInterrupted(Failure, KeyboardInterrupt):
    def _header(self) -> List[str]:
        return [
            "\n",
            f"Command: {self.result.command!r}\n",
            f"Exit code: {self.result.exited}\n",
        ]


class UnexpectedExit(Failure):
    def _header(self) -> List[str]:
        return [
            "Encountered a bad command exit code!\n",
            f"Command: {self.result.command!r}\n",
            f"Exit code: {self.result.exited}\n",
        ]


class CommandTimedOut(Failure):
    def __init__(self, result: RunnersResult, timeout: int):
        super().__init__(result)
        self.timeout = timeout

    def _header(self) -> List[str]:
        return [
            f"Command did not complete within {self.timeout} seconds!\n",
            f"Command: {self.result.command!r}\n",
        ]


Token = int
GenericResult = Union[BaseException, RunnersResult, fabric.transfer.Result]
HostToResult = Dict[str, GenericResult]
TokenizedResult = OrderedDict[Token, GenericResult]

RESULT = TypeVar('RESULT', bound=GenericResult, covariant=True)


class GroupResult(Generic[RESULT]):
    def __init__(self, results: Mapping[str, Sequence[RESULT]]) -> None:
        self._results = results

    def __str__(self) -> str:
        return represent_results(self._results)


class BaseExecutorException(BaseException):
    def __init__(self, results: Mapping[str, Sequence[GenericResult]]):
        self.results = results

    def __str__(self) -> str:
        # We always print output of all commands in the batch even if they are not failed,
        # for the reason that the user code might want to print output of some commands in the batch,
        # but failed to do that because of the exception.
        return represent_results(self.results, hide_already_printed=True)


class GroupInterrupt(BaseExecutorException, KeyboardInterrupt):
    def __str__(self) -> str:
        return '\n' + super().__str__()


class GroupException(BaseExecutorException, errors.GroupException):
    pass


class Callback(ABC):
    """
    Callback to process the result of commands.
    """

    @abstractmethod
    def accept(self, host: str, token: Token, result: RunnersResult) -> None:
        """
        The method is called after the run / sudo command is exited.
        Calling of the method happens sequentially in one thread after some batch of commands is executed on all nodes.

        For the particular host, the order of results with which the method is called
        corresponds to the order of queued commands, for which the given callback was requested.

        :param host: host on which the command was executed
        :param token: identifier of the queued action
        :param result: RunnersResult instance holding the result of the exited command.
        """
        pass


_RawHostToResult = Dict[str, Union[BaseException, fabric.runners.Result, fabric.transfer.Result]]

_Action = Tuple[str, tuple, dict]
_PayloadItem = Tuple[_Action, Optional[Callback], Token]

_T = TypeVar('_T', bound='RawExecutor')


class RawExecutor:

    def __init__(self, cluster: Environment, connection_pool: ConnectionPool = None) -> None:
        self.logger = cluster.log
        if connection_pool is not None:
            self.connection_pool = connection_pool
        else:
            self.connection_pool = cluster.connection_pool
        self._connections_queue: Dict[str, List[_PayloadItem]] = {}
        self._last_token = -1
        self._last_results: Dict[str, TokenizedResult] = {}
        self._command_separator = ''.join(random.choice('=-_') for _ in range(32))
        self._supported_args = {'hide', 'warn', 'pty', 'timeout', 'env', 'out_stream', 'err_stream'}
        self._interrupt_queue = threading.Semaphore(0)
        self._closed = False

    def __enter__(self: _T) -> _T:
        self._check_closed()
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_value: Optional[BaseException],
                 tb: Optional[TracebackType]) -> None:
        if not isinstance(exc_value, KeyboardInterrupt) and self._connections_queue:
            self.flush()

        self._closed = True

    def _check_closed(self) -> None:
        if self._closed:
            raise ValueError("Executor is closed")

    def _actions_mergeable(self, action1: _Action, action2: _Action) -> bool:
        do_type1, _, kwargs1 = action1
        do_type2, _, kwargs2 = action2
        if do_type1 not in ["sudo", "run"] or do_type1 != do_type2:
            return False

        for arg in self._supported_args:
            if arg in ('out_stream', 'err_stream') and kwargs1.get(arg) is kwargs2.get(arg):
                continue

            if arg in ('hide', 'warn', 'pty') and kwargs1.get(arg) == kwargs2.get(arg):
                continue

            # If any action has 'env' param, they are not mergeable.
            # Actions that have specific 'timeout' params are also not mergeable,
            # as we need to apply the specified timeout to the exactly one command.
            if kwargs1.get(arg) is not None or kwargs2.get(arg) is not None:
                return False

        return True

    def _reparse_results(self, raw_results: _RawHostToResult,
                         batch: Dict[str, List[_PayloadItem]]) -> Dict[str, TokenizedResult]:
        reparsed_results: Dict[str, TokenizedResult] = {}
        for host, raw_result in raw_results.items():
            payloads = batch[host]
            conn_results: TokenizedResult = collections.OrderedDict()
            reparsed_results[host] = conn_results

            runner_exception = None
            if isinstance(raw_result, (invoke.UnexpectedExit, invoke.CommandTimedOut, connections.CommandInterrupted)):
                runner_exception = raw_result
                raw_result = raw_result.result

            if not isinstance(raw_result, fabric.runners.Result):
                token = payloads[0][2]
                conn_results[token] = raw_result
                continue

            results = self._reparse_fabric_result(payloads, raw_result)

            for i, result in enumerate(results):
                reparsed_result: GenericResult = result
                _, callback, token = payloads[i]
                if i == len(results) - 1 and runner_exception is not None:
                    if isinstance(runner_exception, connections.CommandInterrupted):
                        # Part of commands were successful until the last reparsed command interrupted.
                        reparsed_result = CommandInterrupted(result)
                    elif isinstance(runner_exception, invoke.UnexpectedExit):
                        # Commands were successful until the last command in the batch.
                        reparsed_result = UnexpectedExit(result)
                    if isinstance(runner_exception, invoke.CommandTimedOut):
                        # Commands were successful until the last reparsed command.

                        # Take common timeout as timeout for the last command.
                        # This is not honest enough, as previous commands also consumed some time.
                        # This is acceptable for an exceptional case when we did not expect long-running command,
                        # as this is applicable only for commands without explicit timeout
                        # (i.e. having timeout=globals.nodes.command_execution.timeout).
                        reparsed_result = CommandTimedOut(result, runner_exception.timeout)

                conn_results[token] = reparsed_result
                if callback is not None and isinstance(reparsed_result, RunnersResult):
                    callback.accept(host, token, reparsed_result)

        return reparsed_results

    def _reparse_fabric_result(self, payloads: List[_PayloadItem],
                               result: fabric.runners.Result) -> List[RunnersResult]:
        # unpack last action in list of payloads
        _, _, kwargs = payloads[-1][0]
        hide = kwargs.get('hide', False)
        pty = kwargs.get('pty', False)

        # Raw stdout may not fully contain the separator,
        # if the channel was interrupted or closed due to a timeout, while reading the separator from the remote output.
        # In this case the part of the separator becomes a part of the reparsed command output.
        # This is acceptable as the situation is considered extremely rare,
        # and because the only we can do with not finished command is to print its partial output.

        # stdout and stderr are combined if pty.
        raw_stderrs = [] if pty else result.stderr.split(self._command_separator)
        raw_stdouts = result.stdout.split(self._command_separator)

        results = []
        result_i = 0
        stdout = stderr = ''
        code = result.exited

        out_i = 0
        err_i = 0
        has_next = True
        while has_next:
            has_next = out_i < len(raw_stdouts) and (pty or err_i < len(raw_stderrs))
            if has_next:
                stdout = raw_stdouts[out_i]
                if not pty:
                    stderr = raw_stderrs[err_i]
                if result_i > 0:
                    # cut LF from the previous "echo <separator>" command
                    stdout = stdout[1:]
                    if not pty:
                        stderr = stderr[1:]

                has_next = out_i + 1 < len(raw_stdouts)
                if has_next:
                    matcher = EXIT_CODE_PATTERN.match(raw_stdouts[out_i + 1])
                    if matcher is not None:
                        code = int(matcher.group(1))
                    else:
                        has_next = False

                has_next = has_next and (pty or err_i + 1 < len(raw_stderrs))

            action, _, _ = payloads[result_i]
            command: str = action[1][0]
            results.append(RunnersResult([command], [code], stdout, stderr, hide=hide))

            stdout = stderr = ''
            code = result.exited
            result_i += 1

            err_i += 1
            out_i += 2

        return results

    def _get_separator(self, kwargs: dict) -> str:
        warn: bool = kwargs.get('warn', False)
        pty: bool = kwargs.get('pty', False)
        if warn:
            separator_symbol = ";"
        else:
            separator_symbol = "&&"

        separator = (
            f" {separator_symbol} "
            f"printf \"%s\\n$?\\n%s\\n\" \"{self._command_separator}\" \"{self._command_separator}\" {separator_symbol} ")
        if not pty:
            separator += f"echo \"{self._command_separator}\" 1>&2 {separator_symbol} "

        return separator

    def _merge_actions(self, payload_items: List[_PayloadItem]) -> List[List[_PayloadItem]]:
        merged_payloads: List[List[_PayloadItem]] = []

        for payload in payload_items:
            if not merged_payloads:
                merged_payloads.append([payload])
                continue

            action = payload[0]
            previous_payloads = merged_payloads[-1]
            previous_action = previous_payloads[-1][0]
            if not self._actions_mergeable(previous_action, action):
                merged_payloads.append(([payload]))
                continue

            previous_payloads.append(payload)

        return merged_payloads

    def _get_callables(self) -> List[Dict[str, List[_PayloadItem]]]:
        callables: Dict[str, List[List[_PayloadItem]]] = {}

        for host, payload_items in self._connections_queue.items():
            callables[host] = self._merge_actions(payload_items)

        i = 0
        batches: List[Dict[str, List[_PayloadItem]]] = []

        while True:
            batch: Dict[str, List[_PayloadItem]] = {}
            for host, actions in callables.items():
                if len(actions) > i:
                    batch[host] = actions[i]
            if not batch:
                break

            i += 1
            batches.append(batch)

        return batches

    def _next_token(self) -> int:
        self._last_token += 1
        return self._last_token

    def queue(self, target: List[str], action: _Action, callback: Callback = None) -> int:
        self._check_closed()
        token = self._next_token()

        do_type, args, kwargs = action
        repr_args = self._repr_args(do_type, args)
        not_supported_args = set(kwargs.keys()) - self._supported_args
        if not_supported_args:
            raise Exception(f"Arguments {', '.join(map(repr, not_supported_args))} are not supported")

        if not target:
            self.logger.verbose('No nodes to perform %s %s with options: %s' % (do_type, repr_args, kwargs))
        else:
            self.logger.verbose(
                'Performing %s %s on nodes %s with options: %s' % (do_type, repr_args, list(target), kwargs))
            for host in target:
                self._connections_queue.setdefault(host, []).append((action, callback, token))

        return token

    def get_last_results(self) -> Dict[str, TokenizedResult]:
        return self._last_results

    def get_flat_result(self) -> Mapping[str, Sequence[GenericResult]]:
        return get_flat_result(self._last_results)

    def flush(self) -> None:
        """
        Flushes the connections' queue and returns grouped result

        :return: grouped tokenized results per connection.
        """
        self._check_closed()
        self._last_results.clear()

        if not self._connections_queue:
            self.logger.verbose('Queue is empty, nothing to perform')
            return

        callable_batches: List[Dict[str, List[_PayloadItem]]] = self._get_callables()

        max_workers = len(self._connections_queue)

        with ThreadPoolExecutor(max_workers=max_workers) as TPE:
            for batch in callable_batches:
                # filter out hosts with failed commands
                batch = {host: payloads for host, payloads in batch.items()
                         # failed command is always last if present
                         if host not in self._last_results
                         or not isinstance(list(self._last_results[host].values())[-1], BaseException)}

                retry = 0
                while True:
                    retry += 1

                    self._do_batch(batch, TPE, self._last_results)
                    batch = self._get_remained_batch(batch)

                    if (not batch or retry >= static.GLOBALS['workaround']['retries']
                            or not self._try_workaround(batch, TPE)):
                        break

                    self.logger.verbose('Retrying #%s...' % retry)
                    time.sleep(static.GLOBALS['workaround']['delay_period'])

        self._connections_queue = {}

        for results in self._last_results.values():
            if any(isinstance(result, BaseException) for result in results.values()):
                raise GroupException(self.get_flat_result())

    def interrupt(self) -> None:
        self._interrupt_queue.release()

    def _prepare_merged_action(self, host: str, payloads: List[_PayloadItem]) -> _Action:
        # unpack last action in list of payloads
        do_type, args, kwargs = payloads[-1][0]

        if do_type == 'get':
            self.logger.verbose('Executing get %s on host %s with options: %s' % (args, host, kwargs))
        if do_type == 'put':
            self.logger.verbose(
                'Executing put %s on host %s with options: %s' % (self._repr_args(do_type, args), host, kwargs))
            if isinstance(args[0], bytes):
                # Each thread should use its own instance of BytesIO.
                args = io.BytesIO(args[0]), args[1]

        if do_type in ('run', 'sudo'):
            if kwargs.get('timeout', None) is None:
                kwargs = {**kwargs, 'timeout': static.GLOBALS['nodes']['command_execution']['timeout']}

            commands: List[str] = [action[1][0] for action, _, _ in payloads]
            self.logger.verbose('Executing %s %s on host %s with options: %s' % (do_type, commands, host, kwargs))

            precommand = ''
            if do_type == 'sudo':
                precommand = 'sudo '

            separator = self._get_separator(kwargs)

            merged_command = (separator + precommand).join(commands)
            args = (merged_command,)

        return do_type, args, kwargs

    @staticmethod
    def _repr_args(do_type: str, args: tuple) -> tuple:
        if do_type == 'put' and isinstance(args[0], bytes):
            return '<text>', args[1]

        return args

    def _flush_logger_writers(self, batch: Dict[str, List[_PayloadItem]]) -> None:
        for payloads in batch.values():
            # Actions are merged only if there are no out_stream/err_stream or if they are the same instance.
            # It is thus enough to take only first action from payloads
            payload = payloads[0]
            action, _, _ = payload
            _, _, kwargs = action
            for stream_key in ('out_stream', 'err_stream'):
                if isinstance(kwargs.get(stream_key), log.LoggerWriter):
                    writer: log.LoggerWriter = kwargs[stream_key]
                    writer.flush(remainder=True)

    def _do_batch(self, batch: Dict[str, List[_PayloadItem]], tpe: ThreadPoolExecutor,
                  capture_results: Dict[str, TokenizedResult]) -> None:
        results: _RawHostToResult = {}
        futures: Dict[str, concurrent.futures.Future] = {}

        def safe_exec(result_map: Dict[str, Any], host: str, call: Callable[[], Any]) -> None:
            try:
                result_map[host] = call()
            except BaseException as e:  # including KeyboardInterrupt
                results[host] = e

        interrupted = False
        try:
            while True:
                try:
                    if not interrupted:
                        for host, payloads in batch.items():
                            cxn = self.connection_pool.get_connection(host)
                            cxn.KM_start()

                            do_type, args, kwargs = self._prepare_merged_action(host, payloads)
                            # pylint: disable-next=cell-var-from-loop
                            safe_exec(futures, host, lambda: tpe.submit(getattr(cxn, do_type), *args, **kwargs))

                    # Timeout is implemented through timeout for run/sudo that finishes the future eventually.
                    # For put/get fabric & paramiko do not offer timeout, so transfer can be stopped only using SIGINT.
                    # The following short-time sleeps allow to implement interruption.
                    not_done = set(futures.values())
                    while not_done := concurrent.futures.wait(not_done, timeout=connections.input_sleep).not_done:
                        if self._interrupt_queue.acquire(blocking=False):  # pylint: disable=consider-using-with
                            raise KeyboardInterrupt()

                except KeyboardInterrupt:
                    interrupted = True
                    for host, payloads in batch.items():
                        cxn = self.connection_pool.get_connection(host)
                        cxn.KM_interrupt()

                    continue

                break
        finally:
            for host, future in futures.items():
                # Only obtain the result of finished futures, thus no timeout
                # pylint: disable-next=cell-var-from-loop
                safe_exec(results, host, lambda: future.result(timeout=None))

        self._flush_logger_writers(batch)

        parsed_results = self._reparse_results(results, batch)
        for host, tokenized_results in parsed_results.items():
            capture_results.setdefault(host, collections.OrderedDict()).update(tokenized_results)

        if interrupted:
            flat_results = get_flat_result(capture_results)
            timed_out = False
            # Check if at least one command was really interrupted.
            # See also `connections.RemoteRunner.wait()`.
            for flat_result in flat_results.values():
                for result in flat_result:
                    if isinstance(result, KeyboardInterrupt):
                        raise GroupInterrupt(flat_results)

                    timed_out = timed_out or isinstance(result, CommandTimedOut)

            # No command was interrupted using real SIGINT character sent, but some command was timed out.
            # This case will be processed later.
            if timed_out:
                return

            # The commands were really finished, but we still need to stop execution of main thread.
            # It seems that no need to print the output.
            raise KeyboardInterrupt()

    def _get_remained_batch(self, batch: Dict[str, List[_PayloadItem]]) -> Dict[str, List[_PayloadItem]]:
        remained_batch = {}
        for host, payloads in batch.items():
            remained_payloads = []
            for payload in payloads:
                _, _, token = payload
                tokenized_results = self._last_results[host]
                # Command is not yet executed or failed.
                # Not yet executed commands can be only after the failed command.
                if token not in tokenized_results or isinstance(tokenized_results[token], BaseException):
                    remained_payloads.append(payload)

            if remained_payloads:
                remained_batch[host] = remained_payloads

        return remained_batch

    def _try_workaround(self, batch: Dict[str, List[_PayloadItem]], tpe: ThreadPoolExecutor) -> bool:
        not_booted = []

        for host in batch:
            # failed command is always last
            exception = list(self._last_results[host].values())[-1]
            if isinstance(exception, CommandTimedOut):
                self.logger.verbose("Command timed out at %s: %s" % (host, str(exception.result)))
                return False
            elif isinstance(exception, UnexpectedExit):
                # Do not str(exception) because it discards output in case of hide=False
                exception_message = str(exception.result)
            else:
                exception_message = str(exception)

            if self._is_allowed_etcd_exception(exception_message):
                self.logger.verbose("Detected ETCD problem at %s, need retry: %s" % (host, exception_message))
            elif self._is_allowed_kubernetes_exception(exception_message):
                self.logger.verbose("Detected kubernetes problem at %s, need retry: %s" % (host, exception_message))
            elif self._is_allowed_connection_exception(exception_message):
                self.logger.verbose("Detected connection exception at %s, will try to reconnect to node. Exception: %s"
                                    % (host, exception_message))
                not_booted.append(host)
            else:
                self.logger.verbose("Detected unavoidable exception at %s, trying to solve automatically: %s"
                                         % (host, exception_message))
                return False

        if not_booted:
            results = self._wait_for_boot_with_executor(not_booted, tpe)
            # if there are not booted nodes, but we succeeded to wait for at least one is booted,
            # we can continue execution
            if all(isinstance(result, BaseException) for result in results.values()):
                return False

        return True

    def wait_for_boot(self, left_nodes: List[str], timeout: int = None,
                      initial_boot_history: Mapping[str, RunnersResult] = None) -> HostToResult:
        with ThreadPoolExecutor(max_workers=len(left_nodes)) as TPE:
            return self._wait_for_boot_with_executor(left_nodes, TPE, timeout, initial_boot_history)

    def _wait_for_boot_with_executor(self, left_nodes: List[str], tpe: ThreadPoolExecutor,
                                     overridden_timeout: int = None,
                                     initial_boot_history: Mapping[str, RunnersResult] = None) -> HostToResult:

        timeout = self._resolve_boot_timeout(left_nodes, overridden_timeout)
        delay_period = static.GLOBALS['nodes']['boot']['defaults']['delay_period']

        if initial_boot_history is None:
            initial_boot_history = {}

        results: HostToResult = {}
        time_start = datetime.now()

        self.logger.verbose("Trying to connect to nodes, timeout is %s seconds..." % timeout)

        # each connection has timeout, so the only we need is to repeat connecting attempts
        # during specified number of seconds
        while True:
            attempt_time_start = datetime.now()
            self._disconnect(left_nodes)

            self.logger.verbose("Attempting to connect to nodes...")
            # this should be invoked without explicit timeout, and relied on fabric Connection timeout instead.
            results.update(self._do_nopasswd(left_nodes, tpe, "last reboot"))
            left_nodes = [host for host, result in results.items()
                          if (isinstance(result, BaseException)
                              # Something is wrong with sudo access. Node is active.
                              and not self.is_require_nopasswd_exception(result)
                              # If not a connection-related exception, do not try to connect further
                              and self._is_allowed_connection_exception(str(result)))
                          or (isinstance(result, RunnersResult)
                              and result == initial_boot_history.get(host))]

            waited = (datetime.now() - time_start).total_seconds()
            if left_nodes:
                timeout = self._resolve_boot_timeout(left_nodes, overridden_timeout)

            if not left_nodes or waited >= timeout:
                break

            self.logger.verbose("Nodes %s are not ready yet, remaining time to wait %i"
                                % (left_nodes, timeout - waited))

            attempt_time = (datetime.now() - attempt_time_start).total_seconds()
            if attempt_time < delay_period:
                time.sleep(delay_period - attempt_time)

        if left_nodes:
            self.logger.verbose("Failed to wait for boot of nodes %s" % left_nodes)
        else:
            self.logger.verbose("All nodes are online now")

        return results

    def _resolve_boot_timeout(self, hosts: List[str], overridden_timeout: Optional[int]) -> int:
        if overridden_timeout is not None:
            return overridden_timeout

        return max(self._get_node_boot_timeout(host) for host in hosts)

    def _get_node_boot_timeout(self, host: str) -> int:
        timeout: int = self.connection_pool.get_node(host)['boot']['timeout']
        return timeout

    def _do_nopasswd(self, left_nodes: List[str], tpe: ThreadPoolExecutor, command: str) -> HostToResult:
        prompt = '[sudo] password: '

        class NoPasswdResponder(invoke.Responder):
            def __init__(self) -> None:
                super().__init__(re.escape(prompt), "")

            def submit(self, stream: str) -> Generator[str, None, None]:
                if self.pattern_matches(stream, self.pattern, "index"):
                    # If user appears to be not a NOPASSWD sudoer, "sudo" suggests to write password.
                    # This is a W/A to handle the situation in a docker container without pseudo-TTY (no -t option)
                    # As long as we require NOPASSWD, we can just fail immediately in such cases.
                    raise invoke.exceptions.ResponseNotAccepted("The user should be a NOPASSWD sudoer")

                # The only acceptable situation, responder does nothing.
                yield from []

        # Currently only NOPASSWD sudoers are supported.
        # Thus, running of connection.sudo("something") should be equal to connection.run("sudo something")
        token = self._next_token()
        action: _Action = ("run", (f"sudo -S -p '{prompt}' {command}",),
                           {"hide": True, "pty": True, "watchers": [NoPasswdResponder()]})
        payload: _PayloadItem = (action, None, token)
        batch = {host: [payload] for host in left_nodes}
        parsed_results: Dict[str, TokenizedResult] = {}
        self._do_batch(batch, tpe, parsed_results)
        return {host: next(iter(results.values())) for host, results in parsed_results.items()}

    @staticmethod
    def is_require_nopasswd_exception(exc: BaseException) -> bool:
        return isinstance(exc, invoke.exceptions.Failure) \
               and isinstance(exc.reason, invoke.exceptions.ResponseNotAccepted)

    @staticmethod
    def _is_allowed_connection_exception(exception_message: str) -> bool:
        exception_message = exception_message.partition('\n')[0]
        for known_exception_message in static.GLOBALS['connection']['bad_connection_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    @staticmethod
    def _is_allowed_etcd_exception(exception_message: str) -> bool:
        for known_exception_message in static.GLOBALS['etcd']['temporary_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    @staticmethod
    def _is_allowed_kubernetes_exception(exception_message: str) -> bool:
        for known_exception_message in static.GLOBALS['kubernetes']['temporary_exceptions']:
            if known_exception_message in exception_message:
                return True

        return False

    def _disconnect(self, hosts: List[str]) -> None:
        for host in hosts:
            self.logger.verbose('Disconnected session with %s' % host)
            cxn = self.connection_pool.get_connection(host)
            cxn.close()


def get_flat_result(results: Dict[str, TokenizedResult]) -> Mapping[str, Sequence[GenericResult]]:
    return {host: list(res.values()) for host, res in results.items()}


def represent_results(flat_results: Mapping[str, Sequence[GenericResult]], hide_already_printed: bool = True) -> str:
    host_outputs = []
    for host, results in flat_results.items():
        output = f"{host}:"

        # filter out transfer results and the last exception if present
        runners_results = [res for res in results if isinstance(res, RunnersResult)]
        if runners_results:
            merged_result = RunnersResult.merge(runners_results)
            output += f" code={merged_result.repr_code()}"
            repr_out = merged_result.repr_out(hide_already_printed=hide_already_printed)
            if repr_out:
                output += '\n\t' + repr_out.replace('\n', '\n\t')

        # The exception may be only the last in the list. We are also sure to have at least one result per node.
        if isinstance(results[-1], BaseException):
            exception = errors.wrap_kme_exception(results[-1])
            output += '\n\t' + str(exception).replace('\n', '\n\t')

        host_outputs.append(output)

    return "\n".join(host_outputs)
