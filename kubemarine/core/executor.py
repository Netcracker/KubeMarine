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
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Tuple, List, Dict, Callable, Any, Optional, Union, OrderedDict, Set, TypeVar, Type

import fabric  # type: ignore[import]
import fabric.transfer  # type: ignore[import]

from concurrent.futures.thread import ThreadPoolExecutor

from kubemarine.core import log
from kubemarine.core.connections import ConnectionPool


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
        if len(results) == 0:
            raise ValueError("At least one result should be present")

        hide = results[0].hide
        commands = []
        stdout = ""
        stderr = ""
        exit_codes = []
        for result in results:
            if result.hide != hide:
                raise ValueError("Cannot merge instances of RunnersResult with different 'hide' property")
            commands.append(result.command)
            stdout += result.stdout
            stderr += result.stderr
            exit_codes.append(result.exited)

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


class UnexpectedExit(Exception):
    def __init__(self, result: RunnersResult):
        self.result = result

    def __str__(self) -> str:
        ret = [
            "Encountered a bad command exit code!\n",
            f"Command: {self.result.command!r}\n",
            f"Exit code: {self.result.exited}\n",
        ]
        repr_out = self.result.repr_out(hide_already_printed=True)
        if repr_out:
            ret.append(repr_out)

        return "\n".join(ret)


Token = int
GenericResult = Union[Exception, RunnersResult, fabric.transfer.Result]
HostToResult = Dict[str, GenericResult]
TokenizedResult = OrderedDict[Token, GenericResult]


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


_RawHostToResult = Dict[str, Union[Exception, fabric.runners.Result, fabric.transfer.Result]]

_Action = Tuple[str, tuple, dict]
_PayloadItem = Tuple[_Action, Optional[Callback], Token]

_T = TypeVar('_T', bound='RawExecutor')


class RawExecutor:

    def __init__(self, logger: log.EnhancedLogger, connection_pool: ConnectionPool,
                 timeout: int = None) -> None:
        self.logger = logger
        self.connection_pool = connection_pool
        self.timeout = timeout
        self._connections_queue: Dict[str, List[_PayloadItem]] = {}
        self._last_token = -1
        self._last_results: Dict[str, TokenizedResult] = {}
        self._command_separator = ''.join(random.choice('=-_') for _ in range(32))
        self._supported_args = {'hide', 'warn', 'timeout', 'watchers', 'env', 'out_stream', 'err_stream'}
        self._closed = False

    def __enter__(self: _T) -> _T:
        self._check_closed()
        return self

    def __exit__(self, exc_type: Optional[Type[Exception]], exc_value: Optional[Exception],
                 tb: Optional[TracebackType]) -> None:
        if self._connections_queue:
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
            if arg in ('out_stream', 'err_stream') and not (kwargs1.get(arg) is kwargs2.get(arg)):
                return False

            if arg in ('env', 'watchers') and (kwargs1.get(arg) is not None or kwargs2.get(arg) is not None):
                return False

            if kwargs1.get(arg) != kwargs2.get(arg):
                return False

        return True

    def _reparse_results(self, results: _RawHostToResult, batch: Dict[str, List[_PayloadItem]],
                         failed_hosts: Set[str]) -> Dict[str, TokenizedResult]:
        reparsed_results: Dict[str, TokenizedResult] = {}
        for host, result in results.items():
            payloads = batch[host]

            conn_results: TokenizedResult = collections.OrderedDict()
            reparsed_results[host] = conn_results
            if not isinstance(result, fabric.runners.Result):
                token = payloads[0][2]
                conn_results[token] = result
                continue

            # unpack last action in list of payloads
            _, _, kwargs = payloads[-1][0]

            stderrs = result.stderr.split(self._command_separator + '\n')
            raw_stdouts = result.stdout.split(self._command_separator + '\n')
            stdouts = []
            exit_codes = []
            i = 0
            while i < len(raw_stdouts):
                stdouts.append(raw_stdouts[i])
                if i + 1 < len(raw_stdouts):
                    exit_codes.append(int(raw_stdouts[i + 1].strip()))
                i += 2
            exit_codes.append(result.exited)
            for i, code in enumerate(exit_codes):
                action, callback, token = payloads[i]
                command: str = action[1][0]
                result = RunnersResult(
                    [command], [code], stdouts[i], stderrs[i], hide=kwargs.get('hide', False))

                # If the last command was exited with non-zero code and warn if False (default),
                # the result is an UnexpectedExit exception.
                if i == len(exit_codes) - 1 and result.exited != 0 and not kwargs.get('warn', False):
                    result = UnexpectedExit(result)
                    failed_hosts.add(host)

                conn_results[token] = result
                if callback is not None and isinstance(result, RunnersResult):
                    callback.accept(host, token, result)

        return reparsed_results

    def _get_separator(self, warn: bool) -> str:
        if warn:
            separator_symbol = ";"
        else:
            separator_symbol = "&&"

        return f" {separator_symbol} " \
               f"printf \"%s\\n$?\\n%s\\n\" \"{self._command_separator}\" \"{self._command_separator}\" {separator_symbol} " \
               f"echo \"{self._command_separator}\" 1>&2 {separator_symbol} "

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
            else:
                i += 1
                batches.append(batch)

        return batches

    def queue(self, target: List[str], action: _Action, callback: Callback = None) -> int:
        self._check_closed()
        self._last_token = token = self._last_token + 1

        do_type, args, kwargs = action
        not_supported_args = set(kwargs.keys()) - self._supported_args
        if not_supported_args:
            raise Exception(f"Arguments {', '.join(map(repr, not_supported_args))} are not supported")

        if not target:
            self.logger.verbose('No nodes to perform %s %s with options: %s' % (do_type, args, kwargs))
        else:
            self.logger.verbose(
                'Performing %s %s on nodes %s with options: %s' % (do_type, args, list(target), kwargs))
            for host in target:
                self._connections_queue.setdefault(host, []).append((action, callback, token))

        return token

    def get_last_results(self) -> Dict[str, TokenizedResult]:
        return self._last_results

    def flush(self) -> None:
        """
        Flushes the connections' queue and returns grouped result

        :return: grouped tokenized results per connection.
        """
        self._check_closed()
        batch_results: Dict[str, TokenizedResult] = {}

        if not self._connections_queue:
            self.logger.verbose('Queue is empty, nothing to perform')
            self._last_results = batch_results
            return

        callable_batches: List[Dict[str, List[_PayloadItem]]] = self._get_callables()

        max_workers = len(self._connections_queue)

        with ThreadPoolExecutor(max_workers=max_workers) as TPE:
            failed_hosts: Set[str] = set()
            for batch in callable_batches:
                results: _RawHostToResult = {}
                futures: Dict[str, concurrent.futures.Future] = {}

                def safe_exec(result_map: Dict[str, Any], host: str, call: Callable[[], Any]) -> None:
                    try:
                        result_map[host] = call()
                    except Exception as e:
                        failed_hosts.add(host)
                        results[host] = e

                for host, payloads in batch.items():
                    if host in failed_hosts:
                        continue
                    cxn = self.connection_pool.get_connection(host)
                    do_type, args, kwargs = self._prepare_merged_action(host, payloads)
                    futures[host] = TPE.submit(getattr(cxn, do_type), *args, **kwargs)

                for host, future in futures.items():
                    safe_exec(results, host, lambda: future.result(timeout=self.timeout))

                self._flush_logger_writers(batch)

                parsed_results: Dict[str, TokenizedResult] = self._reparse_results(results, batch, failed_hosts)
                for host, tokenized_results in parsed_results.items():
                    batch_results.setdefault(host, collections.OrderedDict()).update(tokenized_results)

        self._connections_queue = {}
        self._last_results = batch_results

    def _prepare_merged_action(self, host: str, payloads: List[_PayloadItem]) -> _Action:
        # unpack last action in list of payloads
        do_type, args, kwargs = payloads[-1][0]

        if do_type == 'get':
            self.logger.verbose('Executing get %s on host %s with options: %s' % (args, host, kwargs))
        if do_type == 'put':
            local_stream, remote_file = args
            if isinstance(local_stream, io.BytesIO):
                # Each thread should use its own instance of BytesIO.
                local_stream = io.BytesIO(local_stream.getvalue())
                self.logger.verbose(
                    'Executing put %s on host %s with options: %s' % (('<text>', remote_file), host, kwargs))
            else:
                self.logger.verbose('Executing put %s on host %s with options: %s' % (args, host, kwargs))

            args = (local_stream, remote_file)

        if do_type in ('run', 'sudo'):
            commands: List[str] = [action[1][0] for action, _, _ in payloads]
            self.logger.verbose('Executing %s %s on host %s with options: %s' % (do_type, commands, host, kwargs))

            precommand = ''
            if do_type == 'sudo':
                precommand = 'sudo '

            warn: bool = kwargs.get('warn', False)
            separator = self._get_separator(warn)

            merged_command = (separator + precommand).join(commands)
            args = (merged_command,)

            if not warn:
                kwargs = dict(kwargs)
                # Do not fail when exiting with non-zero code.
                # If 'warn' is initially True, then the exception will be raised during reparsing of result
                kwargs['warn'] = True

        return do_type, args, kwargs

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
