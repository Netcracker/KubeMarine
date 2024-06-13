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

import argparse
import os
import shlex
import sys
import time
from abc import abstractmethod, ABC
from copy import deepcopy
from typing import Optional, List, Union, Sequence, Tuple, Dict, Any

from kubemarine.core import utils, cluster as c, action, resources as res, errors, summary, log, defaults

ERROR_UNRECOGNIZED_CUMULATIVE_POINT_EXCLUDE = "Unrecognized cumulative point to exclude: {point}"
ERROR_UNRECOGNIZED_TASKS_FILTER = "Unrecognized tasks filter: {tasks}"

TASK_DESCRIPTION_TEMPLATE = """
tasks list:
    %s
"""

END_OF_TASKS = object()


class FlowResult:
    def __init__(self, context: dict, logger: log.EnhancedLogger):
        self.context = context
        self.logger = logger


class Flow(ABC):
    def run_flow(self, context: Union[dict, res.DynamicResources], print_summary: bool = True) -> FlowResult:
        time_start = time.time()

        if isinstance(context, res.DynamicResources):
            resources = context
        else:
            resources = res.RESOURCES_FACTORY(context)

        context = resources.context

        try:
            utils.prepare_dump_directory(context)
            resources.logger()
            self._run(resources)
        except (Exception, KeyboardInterrupt) as exc:
            logger = resources.logger_if_initialized()
            if isinstance(exc, errors.FailException):
                # pylint: disable-next=no-member
                utils.do_fail(exc.message, exc.reason, exc.hint, logger=logger)
            else:
                utils.do_fail(f"'{context['initial_procedure'] or 'undefined'}' procedure failed.", exc,
                              logger=logger)

        time_end = time.time()
        logger = resources.logger()

        if print_summary:
            summary.schedule_report(resources.result_context, summary.SummaryItem.EXECUTION_TIME,
                                    utils.get_elapsed_string(time_start, time_end))
            summary.print_summary(resources.result_context, logger)
            logger.info("SUCCESSFULLY FINISHED")

        return FlowResult(resources.result_context, logger)

    @abstractmethod
    def _run(self, resources: res.DynamicResources) -> None:
        pass


class ActionsFlow(Flow):
    def __init__(self, actions: List[action.Action]):
        self._actions = actions

    def _run(self, resources: res.DynamicResources) -> None:
        run_actions(resources, self._actions)


def run_actions(resources: res.DynamicResources, actions: Sequence[action.Action]) -> None:
    """
    Runs actions one by one, recreates inventory when necessary,
    managing such resources as cluster object and inventory.

    Preserve inventory each time it is recreated, or in the end if any actions are successful.
    """

    context = resources.context
    logger = resources.logger()

    successfully_performed: List[str] = []
    cluster: Optional[c.KubernetesCluster] = None
    for act in actions:
        act.prepare_context(context)

        if not successfully_performed:
            # first action in group
            if resources.inventory_filepath:
                with utils.open_external(resources.inventory_filepath, "r") as stream:
                    utils.dump_file(context, stream, "cluster_initial.yaml")

            if resources.procedure_inventory_filepath:
                with utils.open_external(resources.procedure_inventory_filepath, "r") as stream:
                    utils.dump_file(context, stream, "procedure.yaml")

        # Initialize connections early, in particular for inventory preservation.
        resources.cluster(c.EnrichmentStage.LIGHT)

        try:
            logger.info(f"Running action '{act.identifier}'")
            act.run(resources)
            resources.collect_action_result()
            successfully_performed.append(act.identifier)
        except (Exception, KeyboardInterrupt):  # even on KeyboardInterrupt we have to preserve what we have done
            if successfully_performed:
                _post_process_actions_group(resources, cluster, successfully_performed, failed=True)

            raise

        cluster = resources.cluster_if_initialized()

        if act.recreate_inventory:
            if resources.inventory_filepath:
                with utils.open_external(resources.inventory_filepath, "r") as stream:
                    # write original file data to backup file with timestamp
                    timestamp = utils.get_current_timestamp_formatted()
                    inventory_file_basename = os.path.basename(resources.inventory_filepath)
                    utils.dump_file(context, stream, "%s_%s" % (inventory_file_basename, str(timestamp)))

            resources.recreate_inventory()
            _post_process_actions_group(resources, cluster, successfully_performed)
            successfully_performed = []
            cluster = None

    if successfully_performed:
        _post_process_actions_group(resources, cluster, successfully_performed)


def _post_process_actions_group(resources: res.DynamicResources, cluster: Optional[c.KubernetesCluster],
                                successfully_performed: List[str],
                                *,
                                failed: bool = False) -> None:
    previous_successful_cluster = cluster is not None
    try:
        if previous_successful_cluster:
            _dump_inventory(resources, failed)
    finally:
        _preserve_inventory(resources, successfully_performed, failed=failed, enriched=previous_successful_cluster)


def _dump_inventory(resources: res.DynamicResources, failed: bool) -> None:
    context = resources.context

    # If cluster is initialized, it is fully enriched at least to DEFAULT state.
    # Use this state to dump all effective inventories.
    # This is acceptable due to the following assumptions for the last action:
    # * If successful, changes in the inventory should be moved to this state in DynamicResources.recreate_inventory().
    # * If failed, switch to this state effectively restores the cluster to the state after previous action succeeded.
    cluster = resources.cluster(c.EnrichmentStage.DEFAULT)

    if failed:
        # Preserve effective inventory for the last succeeded action.
        # For debug aims, cluster_procedure.yaml can still be used.
        defaults.dump_inventory(cluster, context, 'cluster.yaml')

    resources.dump_finalized_inventory(cluster)


def _preserve_inventory(resources: res.DynamicResources, successfully_performed: List[str],
                        *,
                        failed: bool, enriched: bool) -> None:
    context = resources.context

    context['successfully_performed'] = successfully_performed
    context['status'] = 'failed' if failed else 'successful'

    if (resources.context['preserve_inventory']
            and not resources.context['execution_arguments'].get('without_act', False)):
        # Light cluster is always pre-initialized before running of any action.
        cluster = resources.cluster(c.EnrichmentStage.LIGHT)
        cluster.preserve_inventory(context, enriched=enriched)


class TasksAction(action.Action):
    def __init__(self, identifier: str, tasks: dict,
                 *,
                 cumulative_points: dict = None,
                 tasks_filter: List[str] = None,
                 recreate_inventory: bool = False):
        super().__init__(identifier, recreate_inventory=recreate_inventory)
        self.tasks = deepcopy(tasks)
        self.cumulative_points = cumulative_points or {}
        self.tasks_filter = tasks_filter

    def run(self, resources: res.DynamicResources) -> None:
        """
        Filters and runs tasks.
        """

        args: dict = resources.context['execution_arguments']

        check_cumulative_points(args, self.cumulative_points)

        joined_tasks_filter = ','.join(self.tasks_filter) if self.tasks_filter is not None else args.get('tasks')
        excluded_tasks = args.get('exclude')

        logger = resources.logger()
        logger.debug("Excluded tasks:")
        filtered_tasks, final_list = filter_flow(self.tasks, joined_tasks_filter, excluded_tasks, logger)
        if filtered_tasks == self.tasks:
            logger.debug("\tNo excluded tasks")

        cluster = self.cluster(resources)

        if args.get('without_act', False):
            cluster.log.debug('\nFurther acting manually disabled')
            return

        init_tasks_flow(cluster)
        run_tasks_recursive(self.tasks, final_list, cluster, self.cumulative_points, [])
        proceed_cumulative_point(cluster, self.cumulative_points, END_OF_TASKS,
                                 force=args.get('force_cumulative_points', False))

    def cluster(self, _res: res.DynamicResources) -> c.KubernetesCluster:
        return _res.cluster()


def run_tasks(resources: res.DynamicResources, tasks: dict, cumulative_points: dict = None) -> None:
    return TasksAction("", tasks, cumulative_points=cumulative_points).run(resources)


def create_empty_context(args: dict, procedure: str) -> dict:
    return {
        "execution_arguments": deepcopy(args),
        'initial_procedure': procedure,
        'preserve_inventory': True,
        'make_finalized_inventory': True,
        'load_inventory_silent': False,
        'runtime_vars': {},
        'result': ['summary_report'],
    }


def get_task_list(tasks: dict, _task_path: str = '', leafs_only: bool = True) -> List[str]:
    result = []
    for task_name, task in tasks.items():
        __task_path = _task_path + "." + task_name if _task_path != '' else task_name
        if callable(task) or not leafs_only:
            result.append(__task_path)

        if not callable(task):
            result.extend(get_task_list(task, __task_path, leafs_only))

    return result


def create_context(parser: argparse.ArgumentParser, cli_arguments: Optional[list], procedure: str) -> dict:
    args_list = sys.argv[1:]
    if cli_arguments is not None:
        args_list = cli_arguments

    parser.prog = procedure
    args = vars(parse_args(parser, args_list))

    context = create_empty_context(args=args, procedure=procedure)
    context["initial_cli_arguments"] = ' '.join(map(shlex.quote, args_list))

    return context


def split_strings_list(string_list: Optional[str]) -> List[str]:
    if string_list is None:
        string_list = ''

    return [] if not string_list.strip() else \
        list(filter(bool, map(str.strip, string_list.split(","))))


def check_cumulative_points(args: dict, cumulative_points: dict) -> None:
    exclude_points = args.get('exclude_cumulative_points_methods')
    if not isinstance(exclude_points, list):
        exclude_points = split_strings_list(exclude_points)

    points_list = [point_method.__module__ + '.' + point_method.__qualname__ for point_method in cumulative_points]

    for exclude_point in exclude_points:
        if exclude_point not in points_list:
            raise Exception(ERROR_UNRECOGNIZED_CUMULATIVE_POINT_EXCLUDE.format(point=exclude_point))

    args['exclude_cumulative_points_methods'] = exclude_points


def check_tasks_filter(tasks: dict, tasks_filter: List[str]) -> List[str]:
    tasks_list = get_task_list(tasks, leafs_only=False)

    for tasks_ in tasks_filter:
        if tasks_ not in tasks_list:
            raise Exception(ERROR_UNRECOGNIZED_TASKS_FILTER.format(tasks=tasks_))

    return tasks_filter


def filter_flow(tasks: dict, tasks_filter: Optional[str], excluded_tasks: Optional[str],
                logger: log.EnhancedLogger = None) -> Tuple[dict, List[str]]:
    # Remove any whitespaces from filters, and split by '.'
    tasks_path_filter = [tasks_.split(".") for tasks_ in check_tasks_filter(
        tasks, split_strings_list(tasks_filter))]

    excluded_path_tasks = [tasks_.split(".") for tasks_ in check_tasks_filter(
        tasks, split_strings_list(excluded_tasks))]

    return _filter_flow_internal(tasks, tasks_path_filter, excluded_path_tasks, [], logger)


def _filter_flow_internal(tasks: dict, tasks_filter: List[List[str]], excluded_tasks: List[List[str]],
                          _task_path: List[str],
                          logger: log.EnhancedLogger = None) -> Tuple[dict, List[str]]:
    filtered = {}
    final_list = []

    for task_name, task in tasks.items():
        __task_path = _task_path + [task_name]
        __task_name = ".".join(__task_path)

        allowed = True
        # if task_filter is not empty - smb specified filter argument
        if tasks_filter:
            allowed = False
            # Check if the iterable subpath is in allowed paths. For example, we have to check if
            # ['prepare'] is in allowed path ['prepare', 'cri']
            for task_path in tasks_filter:
                # one of task_path, __task_path is a sublist of another
                # check if current '__task_path' is a sublist only if 'task' is not a final task.
                if (task_path[:len(__task_path)] == __task_path and not callable(task)) \
                        or __task_path[:len(task_path)] == task_path:
                    allowed = True

        if allowed and __task_path not in excluded_tasks:
            if callable(task):
                filtered[task_name] = task
                final_list.append(__task_name)
            else:
                filtered_flow, _final_list = _filter_flow_internal(task, tasks_filter, excluded_tasks, __task_path)
                # there is something to execute in subtree
                if filtered_flow:
                    filtered[task_name] = filtered_flow
                    final_list += _final_list
        elif logger:
            logger.debug("\t%s" % __task_name)

    return filtered, final_list


def run_tasks_recursive(tasks: dict, final_task_names: List[str], cluster: c.KubernetesCluster,
                        cumulative_points: dict, _task_path: List[str]) -> None:
    for task_name, task in tasks.items():
        __task_path = _task_path + [task_name]
        __task_name = ".".join(__task_path)
        run = __task_name in final_task_names

        args = cluster.context['execution_arguments']
        # --force-cumulative-points forcibly run the point only if the related task is going to be executed
        force_cumulative_point = run and args.get('force_cumulative_points', False)
        proceed_cumulative_point(cluster, cumulative_points, __task_name, force=force_cumulative_point)

        if callable(task):
            if not run:
                continue
            cluster.log.info("*** TASK %s ***" % __task_name)
            try:
                task(cluster)
                add_task_to_proceeded_list(cluster, __task_name)
            except (Exception, KeyboardInterrupt) as exc:
                raise errors.FailException(
                    "TASK FAILED %s" % __task_name, exc,
                    hint=cluster.globals['error_handling']['failure_message'] % (sys.argv[0], __task_name)
                )
        else:
            run_tasks_recursive(task, final_task_names, cluster, cumulative_points, __task_path)


def new_common_parser(cli_help: str) -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(description=cli_help,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-c', '--config',
                        default='cluster.yaml',
                        help='define main cluster configuration file')

    parser.add_argument('--ansible-inventory-location',
                        default='ansible-inventory.ini',
                        help='auto-generated ansible-compatible inventory file location')

    parser.add_argument('--dump-location',
                        default='.',
                        help='dump directory for intermediate files')

    parser.add_argument('--disable-dump',
                        action='store_true',
                        help='prevent dump directory creation')

    parser.add_argument('--disable-dump-cleanup',
                        action='store_true',
                        help='prevent dump directory cleaning on process launch')

    parser.add_argument('--log',
                        action='append',
                        nargs='*',
                        help='Logging options, can be specified multiple times')

    parser.add_argument('-w', '--workdir',
                        default='',
                        help='Custom path of the workdir')

    return parser


def new_tasks_flow_parser(cli_help: str, tasks: dict = None) -> argparse.ArgumentParser:
    parser = new_common_parser(cli_help)

    parser.add_argument('--without-act',
                        action='store_true',
                        help='prevent tasks to be executed')

    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('--disable-cumulative-points',
                        action='store_true',
                        help='disable cumulative points execution (use only when you understand what you are doing!)')

    parser.add_argument('--force-cumulative-points',
                        action='store_true',
                        help='force cumulative points execution - they will be executed regardless of whether it was '
                             'scheduled or not (use only when you understand what you are doing!)')

    parser.add_argument('--exclude-cumulative-points-methods',
                        default='',
                        help='comma-separated cumulative points methods names to be excluded from execution')

    # Add tasks list to help section
    if tasks is not None:
        parser.epilog = TASK_DESCRIPTION_TEMPLATE % ('\n    '.join(get_task_list(tasks)))

    return parser


def new_procedure_parser(cli_help: str, optional_config: bool = False, tasks: dict = None) -> argparse.ArgumentParser:
    parser = new_tasks_flow_parser(cli_help, tasks)

    help_msg = 'config file for the procedure'
    if optional_config:
        parser.add_argument('procedure_config', metavar='procedure_config', type=str, help=help_msg, nargs='?')
    else:
        parser.add_argument('procedure_config', metavar='procedure_config', type=str, help=help_msg)

    return parser


def parse_args(parser: argparse.ArgumentParser, arguments: list) -> argparse.Namespace:
    args = parser.parse_args(arguments)

    if args.workdir != '':
        os.chdir(args.workdir)

    return args


def proceed_cumulative_point(cluster: c.KubernetesCluster, points_list: dict,
                             point_task_name: Union[str, object], force: bool = False) -> Dict[str, Any]:
    _check_within_flow(cluster)

    if cluster.context['execution_arguments'].get('disable_cumulative_points', False):
        return {}

    scheduled_methods = cluster.context.get('scheduled_cumulative_points', [])

    results = {}
    for point_method, points_tasks_names in points_list.items():
        if point_task_name in points_tasks_names:

            point_method_fullname = point_method.__module__ + '.' + point_method.__qualname__
            if force:
                cluster.log.verbose('Method %s will be forcibly executed' % point_method_fullname)
            elif point_method not in scheduled_methods:
                cluster.log.verbose('Method %s not scheduled - cumulative point call skipped' % point_method_fullname)
                continue

            cluster.log.info("*** CUMULATIVE POINT %s ***" % point_method_fullname)

            call_result = point_method(cluster)
            if point_method in scheduled_methods:
                scheduled_methods.remove(point_method)
            results[point_method_fullname] = call_result

    return results


def init_tasks_flow(cluster: c.KubernetesCluster) -> None:
    if 'proceeded_tasks' not in cluster.context:
        cluster.context['proceeded_tasks'] = []


def add_task_to_proceeded_list(cluster: c.KubernetesCluster, task_path: str) -> None:
    if not cluster.is_task_completed(task_path):
        cluster.context['proceeded_tasks'].append(task_path)
        utils.dump_file(cluster, "\n".join(cluster.context['proceeded_tasks'])+"\n", 'finished_tasks')


def _check_within_flow(cluster: c.KubernetesCluster, check: bool = True) -> None:
    if check != ('proceeded_tasks' in cluster.context):
        raise NotImplementedError(f"The method is called {'not ' if check else ''}within tasks flow execution")
