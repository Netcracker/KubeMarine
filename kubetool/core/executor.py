import random
import time
from typing import Tuple, List, Dict, Callable, Any, Union
from contextvars import Token, ContextVar

import fabric
import invoke

from fabric.connection import Connection
from concurrent.futures.thread import ThreadPoolExecutor

GRE = ContextVar('KubetoolsGlobalRemoteExecutor', default=None)


class RemoteExecutor:

    def __init__(self, log, lazy=True, parallel=True, ignore_failed=False, enforce_children=False, timeout=None):
        self.log = log
        self.lazy = lazy
        self.parallel = parallel
        self.ignore_failed = ignore_failed
        self.enforce_children = enforce_children
        self.timeout = timeout
        self.connections_queue: Dict[Connection, List[Tuple]] = {}
        self._last_token = -1
        self.previous_context_token = Token.MISSING
        self.command_separator = ''.join(random.choice('=-_') for _ in range(32))
        self.results = []

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

    def _get_active_executor(self):
        executor = GRE.get()
        if executor:
            return executor
        else:
            return self

    def _is_actions_equal(self, action1, action2):
        if action1[0] not in ["sudo", "run"] or action1[0] != action2[0]:
            return False
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
            if isinstance(result, fabric.runners.Result) and executor.command_separator in result.stdout and executor.command_separator in result.stderr:
                stderrs = result.stderr.strip().split(executor.command_separator)
                raw_stdouts = result.stdout.strip().split(executor.command_separator)
                stdouts = []
                exit_codes = []
                i = 0
                while i < len(raw_stdouts):
                    stdouts.append(raw_stdouts[i].strip())
                    if i+1 < len(raw_stdouts):
                        exit_codes.append(int(raw_stdouts[i+1].strip()))
                    i += 2
                exit_codes.append(result.exited)
                for i, code in enumerate(exit_codes):
                    token = tokens[i]
                    conn_results[token] = fabric.runners.Result(stdout=stdouts[i], stderr=stderrs[i], exited=code, connection=conns_by_host[host])
            else:
                conn_results[tokens[0]] = result
            reparsed_results[host] = conn_results
        # TODO: run and collect callbacks and wait for them
        return reparsed_results

    def _merge_actions(self, actions):
        executor = self._get_active_executor()

        if executor.ignore_failed:
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
        executor = self._get_active_executor()
        executor._last_token = token = executor._last_token + 1

        if isinstance(target, Connection):
            target = [Connection]
        if isinstance(target, dict):
            target = list(target.values())

        if not target:
            executor.log.verbose('Connections list is empty, nothing to queue')
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
                output += "\t%s (%s): code=%i" % (conn, token, result.exited)
                if result.stdout:
                    output += "\n\t\tSTDOUT: %s" % result.stdout.replace("\n", "\n\t\t        ")
                if result.stderr:
                    output += "\n\t\tSTDERR: %s" % result.stderr.replace("\n", "\n\t\t        ")

        return output

    def flush(self) -> dict:
        executor = self._get_active_executor()

        batch_results = {}

        if not executor.connections_queue:
            executor.log.verbose('Queue is empty, nothing to perform')
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

                for cxn, payload in batch.items():
                    action, callbacks, tokens = payload
                    do_type, args, kwargs = action
                    executor.log.verbose('Executing %s %s with options: %s' % (do_type, args, kwargs))
                    safe_exec(futures, cxn.host, lambda: TPE.submit(getattr(cxn, do_type), *args, **kwargs))

                for host, future in futures.items():
                    safe_exec(results, host, lambda: future.result(timeout=executor.timeout))

                parsed_results = executor.reparse_results(results, batch)
                for host, tokenized_results in parsed_results.items():
                    if not batch_results.get(host):
                        batch_results[host] = {}
                    for token, res in tokenized_results.items():
                        batch_results[host][token] = res

        executor.reset_queue()
        executor.results.append(batch_results)

        return batch_results
