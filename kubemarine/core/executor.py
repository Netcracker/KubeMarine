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
import random
import time
from typing import Tuple, List, Dict, Callable, Any, Optional, Union, cast, Collection, OrderedDict, Set

import fabric  # type: ignore[import]
import fabric.transfer  # type: ignore[import]

from concurrent.futures.thread import ThreadPoolExecutor

from kubemarine.core import log


class RunnersResult:
    def __init__(self, stdout="", stderr="", exited=0):
        self.stdout = stdout
        self.stderr = stderr
        self.exited = exited

    @property
    def return_code(self):
        return self.exited

    @property
    def ok(self):
        return self.exited == 0

    @property
    def failed(self):
        return not self.ok

    def __bool__(self):
        return self.ok

    def __eq__(self, other):
        if not isinstance(other, RunnersResult):
            return False

        return self.exited == other.exited \
            and self.stdout == other.stdout \
            and self.stderr == other.stderr

    def __ne__(self, other):
        return not (self == other)


Token = int
GenericResult = Union[Exception, RunnersResult, fabric.transfer.Result]
HostToResult = Dict[str, GenericResult]
TokenizedResult = OrderedDict[Token, GenericResult]

_RawHostToResult = Dict[str, Union[Exception, fabric.runners.Result, fabric.transfer.Result]]

_Action = Tuple[str, tuple, dict]
_Callback = Optional[Callable]

_PayloadItem = Tuple[_Action, _Callback, Token]
_MergedPayload = Tuple[_Action, List[_Callback], List[Token]]


class RemoteExecutor:

    def __init__(self, cluster,
                 parallel=True,
                 ignore_failed=False,
                 timeout=None):
        from kubemarine.core.cluster import KubernetesCluster
        self.cluster: KubernetesCluster = cluster
        self.parallel = parallel
        # TODO support ignore_failed option.
        #  Probably it should be chosen automatically depending on warn=? of commands kwargs (not of the same executor option).
        self.ignore_failed = False
        self.timeout = timeout
        self._connections_queue: Dict[str, List[_PayloadItem]] = {}
        self._last_token = -1
        self._last_results: Dict[str, TokenizedResult] = {}
        self._command_separator = ''.join(random.choice('=-_') for _ in range(32))
        self._supported_args = {'hide', 'warn', 'timeout', 'watchers', 'env', 'out_stream', 'err_stream'}

    def __enter__(self):
        _GRE_STACK.append(self)
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if not (self is get_active_executor()):
            raise Exception("Unexpected condition: leaving executor is not active")
        _GRE_STACK.pop()
        if self._connections_queue:
            self.flush()

    def _actions_mergeable(self, action1: _Action, action2: _Action):
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

    def _reparse_results(self, results: _RawHostToResult, batch: Dict[str, _MergedPayload]) \
            -> Dict[str, TokenizedResult]:
        reparsed_results: Dict[str, TokenizedResult] = {}
        for host, result in results.items():
            if isinstance(result, fabric.runners.Result):
                result = RunnersResult(result.stdout, result.stderr, result.exited)

            conn_results: TokenizedResult = collections.OrderedDict()
            action, callbacks, tokens = batch[host]
            if (isinstance(result, RunnersResult)
                    and self._command_separator in result.stdout
                    and self._command_separator in result.stderr):
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
                    token = tokens[i]
                    conn_results[token] = RunnersResult(stdouts[i], stderrs[i], code)
            else:
                conn_results[tokens[0]] = result
            reparsed_results[host] = conn_results
        # TODO: In long term run, collect callbacks and wait for them
        return reparsed_results

    def _merge_actions(self, payload_items: List[_PayloadItem]) -> List[_MergedPayload]:
        if self.ignore_failed:
            # todo exit codes in separators do not work, because 'echo _command_separator' always rewrites exit code to 0
            separator_symbol = ";"
        else:
            separator_symbol = "&&"

        separator = f" {separator_symbol} " \
                    f"echo \"{self._command_separator}\" {separator_symbol} " \
                    f"echo $? {separator_symbol} " \
                    f"echo \"{self._command_separator}\" {separator_symbol} " \
                    f"echo \"{self._command_separator}\" 1>&2 {separator_symbol} "

        merged_payloads: List[_MergedPayload] = []

        for payload in payload_items:
            action, callback, token = payload
            if not merged_payloads:
                merged_payloads.append((action, [callback], [token]))
                continue

            previous_action, callbacks, tokens = merged_payloads[-1]
            if not self._actions_mergeable(previous_action, action):
                merged_payloads.append((action, [callback], [token]))
                continue

            do_type, _, kwargs = previous_action

            precommand = ''
            if do_type == 'sudo':
                precommand = 'sudo '

            merged_action_command: str = previous_action[1][0] + separator + precommand + action[1][0]
            merged_action: _Action = (do_type, (merged_action_command,), kwargs)
            callbacks.append(callback)
            tokens.append(token)
            merged_payloads[-1] = (merged_action, callbacks, tokens)

        return merged_payloads

    def _get_callables(self) -> List[Dict[str, _MergedPayload]]:
        callables: Dict[str, List[_MergedPayload]] = {}

        for host, payload_items in self._connections_queue.items():
            callables[host] = self._merge_actions(payload_items)

        i = 0
        batches: List[Dict[str, _MergedPayload]] = []

        while True:
            batch: Dict[str, _MergedPayload] = {}
            for host, actions in callables.items():
                if len(actions) > i:
                    batch[host] = actions[i]
            if not batch:
                break
            else:
                i += 1
                batches.append(batch)

        return batches

    def queue(self, target: Collection[str], action: _Action, callback: Callable = None) -> int:
        # TODO support callbacks
        callback = None
        self._last_token = token = self._last_token + 1

        do_type, args, kwargs = action
        not_supported_args = set(kwargs.keys()) - self._supported_args
        if not_supported_args:
            raise Exception(f"Arguments {', '.join(map(repr, not_supported_args))} are not supported")

        if not target:
            self.cluster.log.verbose('No nodes to perform %s %s with options: %s' % (do_type, args, kwargs))
        else:
            self.cluster.log.verbose(
                'Performing %s %s on nodes %s with options: %s' % (do_type, args, list(target), kwargs))
            for host in target:
                self._connections_queue.setdefault(host, []).append((action, callback, token))

        return token

    def get_last_results(self) -> Dict[str, TokenizedResult]:
        return self._last_results

    def _merge_results(self, filter_tokens: Optional[List[int]] = None) -> HostToResult:
        group_results: HostToResult = {}
        for host, host_results in self.get_last_results().items():
            merged_result = RunnersResult()
            object_result = None

            tokens = host_results.keys() if filter_tokens is None else filter_tokens
            for token, result in host_results.items():
                if isinstance(result, Exception):
                    object_result = result
                    break
                elif token not in tokens:
                    continue

                if isinstance(result, RunnersResult):
                    if result.stdout:
                        merged_result.stdout += result.stdout
                    if result.stderr:
                        merged_result.stderr += result.stderr

                    # Exit codes can not be merged, that's why they are assigned by priority:
                    # 1. Most important code is 1, it should be assigned if any results contains it
                    # 2. Non-zero exit code from last command
                    # 3. Zero exit code, when all commands succeeded
                    if result.exited == 1 or (
                            merged_result.exited != 1 and result.exited != merged_result.exited):
                        merged_result.exited = result.exited
                else:
                    object_result = result

            # Some commands can produce non-parsed objects, like 'timeout'
            # In that case it is impossible to merge something, and last such an "object" should be passed as a result
            if object_result is not None:
                group_results[host] = object_result
            else:
                group_results[host] = merged_result

        return group_results

    def get_merged_nodegroup_result(self, filter_tokens: Optional[List[int]] = None):
        """
        Returns last results, merged into simple NodeGroupResult.
        If any node failed, throws GroupException.

        The method can be useful to check exceptions.
        To check the result, use get_merged_runners_result().

        :param filter_tokens: tokens to filter result of specific commands in the batch
        :return: NodeGroupResult
        """

        # Throw any exceptions ONLY when no handlers waits for results. For non-queued results any exceptions should
        # handled via _do_with_wa() or other parent error handling mechanism.
        # For queued flushes, exception handling with W/A is currently not supported.
        # TODO: Merge results/exceptions handling with kubemarine.core.group.NodeGroup._do_with_wa to avoid code dup

        results = self._merge_results(filter_tokens=filter_tokens)
        # TODO: Get rid of this WA import, added to avoid circular import problem
        from kubemarine.core.group import NodeGroupResult, GroupException
        group_result = NodeGroupResult(self.cluster, results)
        if len(group_result.failed) > 0:
            # If any failed, then throw exception.
            # Do not check 'warn' arg, because if any command had 'False' value, UnexpectedExit can be already thrown.
            raise GroupException(group_result)

        return group_result

    def get_merged_runners_result(self, filter_tokens: Optional[List[int]] = None):
        """
        Returns last results, merged into simple RunnersGroupResult.
        If any node failed, throws GroupException.
        If failed convert to the runners result (e.g. if put/get commands were in the batch), throws Exception.

        The method can be useful to
        1) check exceptions,
        2) check result in case only one command per node is executed,
        3) check result of specific commands in the batch if filter_tokens parameter is provided.
        4) merge the result to print it to logs.

        For more fine-grained control, use get_last_results().

        :param filter_tokens: tokens to filter result of specific commands in the batch
        :return: RunnersGroupResult
        """
        # TODO: Get rid of this WA import, added to avoid circular import problem
        from kubemarine.core.group import RunnersGroupResult

        group_result = self.get_merged_nodegroup_result(filter_tokens=filter_tokens)
        for result in group_result.values():
            if not isinstance(result, RunnersResult):
                raise Exception("Cannot convert transfer result to the simple runners result")

        return RunnersGroupResult(self.cluster,
                                  {host: cast(RunnersResult, res) for host, res in group_result.items()})

    def flush(self) -> Dict[str, TokenizedResult]:
        """
        Flushes the connections' queue.
        Returns grouped result, or throws GroupException in case of any failure.

        :return: grouped tokenized results per connection.
        """
        batch_results: Dict[str, TokenizedResult] = {}

        if not self._connections_queue:
            self.cluster.log.verbose('Queue is empty, nothing to perform')
            self._last_results = batch_results
            return batch_results

        callable_batches: List[Dict[str, _MergedPayload]] = self._get_callables()

        max_workers = len(self._connections_queue)
        if not self.parallel:
            max_workers = 1

        with ThreadPoolExecutor(max_workers=max_workers) as TPE:
            failed_hosts: Set[str] = set()
            for batch in callable_batches:
                results: _RawHostToResult = {}
                futures: Dict[str, concurrent.futures.Future] = {}

                def safe_exec(result_map: Dict[str, Any], host: str, call: Callable[[], Any]) -> None:
                    try:
                        # sleep required to avoid thread starvation
                        time.sleep(0.1)
                        result_map[host] = call()
                        time.sleep(0.1)
                    except Exception as e:
                        failed_hosts.add(host)
                        results[host] = e

                for host, payload in batch.items():
                    if host in failed_hosts:
                        continue
                    cxn = self.cluster.connection_pool.get_connection(host)
                    action, callbacks, tokens = payload
                    do_type, args, kwargs = action
                    self.cluster.log.verbose('Executing %s %s with options: %s' % (do_type, args, kwargs))
                    safe_exec(futures, host, lambda: TPE.submit(getattr(cxn, do_type), *args, **kwargs))

                for host, future in futures.items():
                    safe_exec(results, host, lambda: future.result(timeout=self.timeout))

                self._flush_logger_writers(batch)

                parsed_results: Dict[str, TokenizedResult] = self._reparse_results(results, batch)
                for host, tokenized_results in parsed_results.items():
                    batch_results.setdefault(host, collections.OrderedDict()).update(tokenized_results)

        self._connections_queue = {}
        self._last_results = batch_results

        self.get_merged_nodegroup_result()

        return batch_results

    def _flush_logger_writers(self, batch: Dict[str, _MergedPayload]):
        for payload in batch.values():
            action, _, _ = payload
            _, _, kwargs = action
            for stream_key in ('out_stream', 'err_stream'):
                if isinstance(kwargs.get(stream_key), log.LoggerWriter):
                    writer: log.LoggerWriter = kwargs[stream_key]
                    writer.flush(remainder=True)


# Cannot annotate in Python 3.7
# https://github.com/python/cpython/issues/79120
_GRE_STACK = []  # type: ignore[var-annotated]


def is_executor_active() -> bool:
    return bool(_GRE_STACK)


def get_active_executor() -> RemoteExecutor:
    if not _GRE_STACK:
        raise Exception("Trying to access last active executor out of any executor context")

    return _GRE_STACK[-1]
