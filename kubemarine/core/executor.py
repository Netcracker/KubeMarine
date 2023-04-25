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

import random
import time
from typing import Tuple, List, Dict, Callable, Any, Optional
from contextvars import Token, ContextVar

import fabric
import invoke

from fabric.connection import Connection
from concurrent.futures.thread import ThreadPoolExecutor

GRE = ContextVar('KubemarineGlobalRemoteExecutor', default=None)


class RemoteExecutor:

    def __init__(self, cluster,
                 warn=False,
                 lazy=True,
                 parallel=True,
                 ignore_failed=False,
                 enforce_children=False,
                 timeout=None):
        self.cluster = cluster
        # TODO revise necessity of warn option
        self.warn = False
        self.lazy = lazy
        self.parallel = parallel
        # TODO support ignore_failed option.
        #  Probably it should be chosen automatically depending on warn=? of commands kwargs (not of the same executor option).
        self.ignore_failed = False
        # TODO revise this option
        self.enforce_children = False
        self.timeout = timeout
        self.connections_queue: Dict[Connection, List[Tuple]] = {}
        self._last_token = -1
        self.previous_context_token = Token.MISSING
        self.command_separator = ''.join(random.choice('=-_') for _ in range(32))
        self.results = []
        self.connections_queue_history = []

    def __del__(self):
        pass

    def __enter__(self):
        executor = self._get_active_executor()
        if executor == self or not executor.enforce_children:
            self.previous_context_token = GRE.set(self)
        return executor

    def __exit__(self, exc_type, exc_value, tb):
        if self.previous_context_token != Token.MISSING:
            GRE.reset(self.previous_context_token)
        if self.connections_queue:
            self.flush()
            # Throw any exceptions ONLY when no handlers waits for results. For non-queued results any exceptions should
            # handled via _do() or other parent error handling mechanism. When queue flushed inside RemoteExecutor
            # context block, then nobody can handle results, so RemoteExecutor should throw an error by itself.
            # TODO: Merge results/exceptions handling with kubemarine.core.group.NodeGroup._do_with_wa to avoid code dup
            if not self.warn:
                self.throw_on_failed()

    def _get_active_executor(self):
        executor = GRE.get()
        if executor:
            return executor
        else:
            return self

    def _is_actions_equal(self, action1, action2):
        if action1[0] not in ["sudo", "run"] or action1[0] != action2[0]:
            return False
        # todo bug, what if one kwargs dict is a subdict of another?
        for key, value in action1[2].items():
            if value != action2[2].get(key):
                return False
        return True

    def reparse_results(self, results, batch):
        batch_no_cnx: Dict[str, tuple] = {}
        conns_by_host: Dict[str, Connection] = {}
        for cnx, data in batch.items():
            batch_no_cnx[cnx.host] = data
            conns_by_host[cnx.host] = cnx
        executor = self._get_active_executor()
        reparsed_results = {}
        for host, result in results.items():
            conn_results = {}
            action, callbacks, tokens = batch_no_cnx[host]
            if isinstance(result,
                          fabric.runners.Result) and executor.command_separator in result.stdout and executor.command_separator in result.stderr:
                stderrs = result.stderr.split(executor.command_separator + '\n')
                raw_stdouts = result.stdout.split(executor.command_separator + '\n')
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
                    conn_results[token] = fabric.runners.Result(stdout=stdouts[i], stderr=stderrs[i], exited=code,
                                                                connection=conns_by_host[host])
            else:
                conn_results[tokens[0]] = result
            reparsed_results[conns_by_host[host]] = conn_results
        # TODO: In long term run, collect callbacks and wait for them
        return reparsed_results

    def _merge_actions(self, actions):
        executor = self._get_active_executor()

        if executor.ignore_failed:
            # todo exit codes in separators do not work, because 'echo command_separator' always rewrites exit code to 0
            separator_symbol = ";"
        else:
            separator_symbol = "&&"

        separator = f" {separator_symbol} " \
                    f"echo \"{executor.command_separator}\" {separator_symbol} " \
                    f"echo $? {separator_symbol} " \
                    f"echo \"{executor.command_separator}\" {separator_symbol} " \
                    f"echo \"{executor.command_separator}\" 1>&2 {separator_symbol} "

        merged_actions = []

        for payload in actions:
            action, callback, token = payload
            if merged_actions and executor._is_actions_equal(merged_actions[-1][0], action):
                precommand = ''
                if action[0] == 'sudo':
                    precommand = 'sudo '
                previous_action = merged_actions[-1][0]
                merged_action_command = previous_action[1][0] + separator + precommand + action[1][0]
                merged_actions[-1][0] = (previous_action[0], tuple([merged_action_command]), previous_action[2])
                merged_actions[-1][1].append(callback)
                merged_actions[-1][2].append(token)
            else:
                merged_actions.append([action, [callback], [token]])

        return merged_actions

    def _get_callables(self):
        executor = self._get_active_executor()
        callables = {}

        for connection, actions in executor.connections_queue.items():
            callables[connection] = executor._merge_actions(actions)

        i = 0
        batches = []

        while i != -1:
            batch = {}
            for conn, actions in callables.items():
                if len(actions) > i:
                    batch[conn] = actions[i]
            if not batch:
                i = -1
            else:
                i += 1
                batches.append(batch)

        return batches

    def queue(self, target, action: Tuple, callback: Callable = None) -> int or dict:
        # TODO support callbacks
        callback = None
        executor = self._get_active_executor()
        executor._last_token = token = executor._last_token + 1

        if isinstance(target, Connection):
            target = [Connection]
        if isinstance(target, dict):
            target = list(target.values())

        if not target:
            executor.cluster.log.verbose('Connections list is empty, nothing to queue')
        else:
            for connection in target:
                if not executor.connections_queue.get(connection):
                    executor.connections_queue[connection] = []
                executor.connections_queue[connection].append((action, callback, token))

        if not executor.lazy:
            return executor.flush()
        else:
            return token

    def reset_queue(self) -> None:
        executor = self._get_active_executor()
        executor.connections_queue = {}

    def get_last_results(self):
        executor = self._get_active_executor()
        if len(executor.results) == 0:
            return None
        return executor.results[-1]

    def get_merged_nodegroup_results(self, filter_tokens: Optional[List[int]] = None):
        """
        Merges last tokenized results into NodeGroupResult.

        The method is useful to check exceptions, to check result in case only one command per node is executed,
        or to check result of specific commands in the batch if filter_tokens parameter is provided.

        :param filter_tokens: tokens to filter result of specific commands in the batch
        :return: None or NodeGroupResult
        """
        # TODO: Get rid of this WA import, added to avoid circular import problem
        from kubemarine.core.group import NodeGroupResult
        executor = self._get_active_executor()
        if len(executor.results) == 0:
            return None
        group_results = NodeGroupResult(self.cluster)
        for cxn, host_results in executor.get_last_results().items():
            merged_result = {
                "stdout": '',
                "stderr": '',
                "exited": 0
            }
            object_result = None

            tokens = host_results.keys() if filter_tokens is None else filter_tokens
            for token, result in host_results.items():
                if isinstance(result, Exception):
                    object_result = result
                    continue
                elif token not in tokens:
                    continue

                if isinstance(result, fabric.runners.Result):
                    if result.stdout:
                        merged_result['stdout'] += result.stdout
                    if result.stderr:
                        merged_result['stderr'] += result.stderr

                    # Exit codes can not be merged, that's why they are assigned by priority:
                    # 1. Most important code is 1, it should be assigned if any results contains it
                    # 2. Non-zero exit code from last command
                    # 3. Zero exit code, when all commands succeeded
                    if result.exited == 1 or (
                            merged_result['exited'] != 1 and result.exited != merged_result['exited']):
                        merged_result['exited'] = result.exited
                else:
                    object_result = result

            # Some commands can produce non-parsed objects, like 'timeout'
            # In that case it is impossible to merge something, and last such an "object" should be passed as a result
            if object_result is not None:
                group_results[cxn] = object_result
            else:
                group_results[cxn] = fabric.runners.Result(stdout=merged_result['stdout'],
                                                           stderr=merged_result['stderr'],
                                                           exited=merged_result['exited'],
                                                           connection=cxn)
        return group_results

    def throw_on_failed(self):
        """
        Throws an exception if last results has failed commands. Ignores enabled executor.warn option.
        :return: None
        """
        self.get_merged_result()

    def get_merged_result(self):
        """
        Returns last results, merged into NodeGroupResult. If any node failed, throws GroupException.

        The method is useful to propagate exceptions, or to check result in case only one command per node is executed.

        :return: NodeGroupResult
        """
        executor = self._get_active_executor()
        if len(executor.results) == 0:
            return None
        group_results = executor.get_merged_nodegroup_results()
        if len(group_results.failed) > 0:
            # If any failed, then throw exception.
            # Do not check 'warn' arg, because if any command had 'False' value, UnexpectedExit can be already thrown.
            raise fabric.group.GroupException(group_results)

        return group_results

    def get_last_results_str(self):
        batched_results = self.get_last_results()
        if not batched_results:
            return
        output = ""
        for conn, results in batched_results.items():
            for token, result in results.items():
                if isinstance(result, invoke.exceptions.UnexpectedExit):
                    result = result.result

                # for now we do not know how-to print transfer result
                if not isinstance(result, fabric.runners.Result):
                    continue

                if output != "":
                    output += "\n"
                output += "\t%s (%s): code=%i" % (conn.host, token, result.exited)
                if result.stdout:
                    output += "\n\t\tSTDOUT: %s" % result.stdout.replace("\n", "\n\t\t        ")
                if result.stderr:
                    output += "\n\t\tSTDERR: %s" % result.stderr.replace("\n", "\n\t\t        ")

        return output

    def print_last_results(self) -> None:
        """
        Prints debug message to log with last executed queued command results.
        :return: None
        """
        results = self.get_last_results_str()
        self.cluster.log.debug(results)

    def flush(self) -> dict:
        executor = self._get_active_executor()

        batch_results = {}

        if not executor.connections_queue:
            executor.cluster.log.verbose('Queue is empty, nothing to perform')
            return batch_results

        callable_batches = executor._get_callables()

        max_workers = len(executor.connections_queue.keys())
        if not executor.parallel:
            max_workers = 1

        with ThreadPoolExecutor(max_workers=max_workers) as TPE:
            for batch in callable_batches:
                results = {}
                futures = {}

                def safe_exec(result_map: Dict[str, Any], key: str, call: Callable[[], Any]):
                    try:
                        # sleep required to avoid thread starvation
                        time.sleep(0.1)
                        result_map[key] = call()
                        time.sleep(0.1)
                    except Exception as e:
                        results[key] = e

                # todo if previous batch for some cxn failed, probably we should not continue executing for that cxn
                for cxn, payload in batch.items():
                    action, callbacks, tokens = payload
                    do_type, args, kwargs = action
                    executor.cluster.log.verbose('Executing %s %s with options: %s' % (do_type, args, kwargs))
                    safe_exec(futures, cxn.host, lambda: TPE.submit(getattr(cxn, do_type), *args, **kwargs))

                for host, future in futures.items():
                    safe_exec(results, host, lambda: future.result(timeout=executor.timeout))

                parsed_results = executor.reparse_results(results, batch)
                for host, tokenized_results in parsed_results.items():
                    if not batch_results.get(host):
                        batch_results[host] = {}
                    for token, res in tokenized_results.items():
                        batch_results[host][token] = res

        executor.connections_queue_history.append(executor.connections_queue)
        executor.reset_queue()
        executor.results.append(batch_results)

        return batch_results
