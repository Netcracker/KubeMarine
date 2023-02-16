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
from copy import deepcopy
from typing import Type, Optional, List, Union

from kubemarine.core import utils, cluster as c, action, resources as res, errors, summary

DEFAULT_CLUSTER_OBJ: Optional[Type[c.KubernetesCluster]] = None
TASK_DESCRIPTION_TEMPLATE = """
tasks list:
    %s
"""

END_OF_TASKS = object()


def run_actions(context: Union[dict, res.DynamicResources], actions: List[action.Action],
                print_summary: bool = True) -> Optional[c.KubernetesCluster]:
    """
    Runs actions one by one, recreates inventory when necessary,
    managing such resources as cluster object and raw inventory.

    For each initialized cluster object, preserves inventory if any action is succeeded.
    """
    time_start = time.time()

    resources: res.DynamicResources = context
    if isinstance(context, dict):
        resources = res.DynamicResources(context)

    context = resources.context

    args: dict = context['execution_arguments']
    if not args.get('disable_dump', True):
        utils.prepare_dump_directory(args.get('dump_location'),
                                     reset_directory=not args.get('disable_dump_cleanup', False))

    log = resources.logger()

    successfully_performed = []
    last_cluster = None
    for act in actions:
        act.prepare_context(resources.context)

        if not successfully_performed:
            # first action in group
            if resources.inventory_filepath:
                with utils.open_external(resources.inventory_filepath, "r") as stream:
                    utils.dump_file(context, stream, "cluster_initial.yaml")

            if resources.procedure_inventory_filepath:
                with utils.open_external(resources.procedure_inventory_filepath, "r") as stream:
                    utils.dump_file(context, stream, "procedure.yaml")
        try:
            log.info(f"Running action '{act.identifier}'")
            act.run(resources)
            successfully_performed.append(act.identifier)
        except Exception as exc:
            if successfully_performed:
                _post_process_actions_group(last_cluster, context, successfully_performed, failed=True)

            if isinstance(exc, errors.FailException):
                utils.do_fail(exc.message, exc.reason, exc.hint, log=log)
            else:
                utils.do_fail(f"'{context['initial_procedure'] or 'undefined'}' procedure failed.", exc,
                              log=log)

        last_cluster = resources.cluster_if_initialized()

        if act.recreate_inventory:
            if resources.inventory_filepath:
                with utils.open_external(resources.inventory_filepath, "r") as stream:
                    # write original file data to backup file with timestamp
                    timestamp = utils.get_current_timestamp_formatted()
                    inventory_file_basename = os.path.basename(resources.inventory_filepath)
                    utils.dump_file(context, stream, "%s_%s" % (inventory_file_basename, str(timestamp)))

            resources.recreate_inventory()
            _post_process_actions_group(last_cluster, context, successfully_performed)
            successfully_performed = []
            last_cluster = None

    if successfully_performed:
        _post_process_actions_group(last_cluster, context, successfully_performed)

    time_end = time.time()

    if print_summary:
        summary.schedule_report(resources.working_context, summary.SummaryItem.EXECUTION_TIME,
                                utils.get_elapsed_string(time_start, time_end))
        summary.print_summary(resources.working_context, log)
        log.info("SUCCESSFULLY FINISHED")

    return last_cluster


def _post_process_actions_group(last_cluster: c.KubernetesCluster, context: dict,
                                successfully_performed: list, failed=False):
    if last_cluster is None:
        return
    try:
        last_cluster.dump_finalized_inventory()
    finally:
        if context['preserve_inventory']:
            last_cluster.context['successfully_performed'] = successfully_performed
            last_cluster.context['status'] = 'failed' if failed else 'successful'
            last_cluster.preserve_inventory()

        # TODO remove in next release
        if last_cluster.context.get('schema_errors_ignored'):
            last_cluster.log.warning(
                "Inventory file is failed to be validated against the schema, "
                "that was suppressed with --ignore-schema-errors.\n"
                "See the beginning of the logs for details.\n"
                "The option will be removed in next release.")


def run_tasks(resources: res.DynamicResources, tasks, cumulative_points=None, tasks_filter: list = None):
    """
    Filters and runs tasks.
    """

    if cumulative_points is None:
        cumulative_points = {}

    args: dict = resources.context['execution_arguments']

    tasks_filter = tasks_filter if tasks_filter is not None \
        else [] if not args.get('tasks') else args['tasks'].split(",")
    excluded_tasks = [] if not args.get('exclude') else args['exclude'].split(",")

    print("Excluded tasks:")
    filtered_tasks, final_list = filter_flow(tasks, tasks_filter, excluded_tasks)
    if filtered_tasks == tasks:
        print("\tNo excluded tasks")

    cluster = resources.cluster()

    if args.get('without_act', False):
        resources.context['preserve_inventory'] = False
        cluster.log.debug('\nFurther acting manually disabled')
        return

    init_tasks_flow(cluster)
    run_flow(tasks, final_list, cluster, cumulative_points, [])
    proceed_cumulative_point(cluster, cumulative_points, END_OF_TASKS,
                             force=args.get('force_cumulative_points', False))


def create_empty_context(args: dict = None, procedure: str = None):
    if args is None:
        args = {}
    return {
        "execution_arguments": deepcopy(args),
        "nodes": {},
        'initial_procedure': procedure,
        'preserve_inventory': True,
        'runtime_vars': {}
    }


def get_task_list(tasks, _task_path=''):
    result = []
    for task_name, task in tasks.items():
        __task_path = _task_path + "." + task_name if _task_path != '' else task_name
        result.extend(get_task_list(task, __task_path) if not callable(task) else [__task_path])
    return result


def create_context(parser: argparse.ArgumentParser, cli_arguments: list, procedure: str = None):
    parser.prog = procedure
    args = vars(parse_args(parser, cli_arguments))

    if args.get('exclude_cumulative_points_methods', '').strip() != '':
        args['exclude_cumulative_points_methods'] = args['exclude_cumulative_points_methods'].strip().split(",")
        # print('The following cumulative points methods are marked for exclusion: [ %s ]' %
        #               ', '.join(args['exclude_cumulative_points_methods']))
    else:
        args['exclude_cumulative_points_methods'] = []

    context = create_empty_context(args=args, procedure=procedure)
    context["initial_cli_arguments"] = ' '.join(map(shlex.quote, cli_arguments))

    return context


def filter_flow(tasks, tasks_filter: List[str], excluded_tasks: List[str]):
    # Remove any whitespaces from filters, and split by '.'
    tasks_filter = [tasks.split(".") for tasks in list(map(str.strip, tasks_filter))]
    excluded_tasks = [tasks.split(".") for tasks in list(map(str.strip, excluded_tasks))]

    return _filter_flow_internal(tasks, tasks_filter, excluded_tasks, [])


def _filter_flow_internal(tasks, tasks_filter: List[List[str]], excluded_tasks: List[List[str]], _task_path: List[str]):
    filtered = {}
    final_list = []

    for task_name, task in tasks.items():
        __task_path = _task_path + [task_name]
        __task_name = ".".join(__task_path)

        allowed = True
        # if task_filter is not empty - smb specified filter argument
        if tasks_filter:
            allowed = False
            # Check if the iterable subpath is in allowed paths. For example we have to check if
            # system_prepare.cri in allowed path system_prepare.cri.docker
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
        else:
            print("\t%s" % __task_name)

    return filtered, final_list


def run_flow(tasks: dict, final_task_names: List[str], cluster: c.KubernetesCluster,
             cumulative_points: dict, _task_path: List[str]):
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
            except Exception as exc:
                raise errors.FailException(
                    "TASK FAILED %s" % __task_name, exc,
                    hint=cluster.globals['error_handling']['failure_message'] % (sys.argv[0], __task_name)
                )
        else:
            run_flow(task, final_task_names, cluster, cumulative_points, __task_path)


def new_common_parser(cli_help):

    parser = argparse.ArgumentParser(description=cli_help,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-c', '--config',
                        default='cluster.yaml',
                        help='define main cluster configuration file')

    parser.add_argument('--ansible-inventory-location',
                        default='./ansible-inventory.ini',
                        help='auto-generated ansible-compatible inventory file location')

    parser.add_argument('--dump-location',
                        default='./dump/',
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

    # TODO remove in next release
    parser.add_argument('--ignore-schema-errors',
                        action='store_true',
                        help='Do not stop the run if validation by schema fails. '
                             'The option will be removed in next release.')

    return parser


def new_tasks_flow_parser(cli_help, tasks=None):
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


def new_procedure_parser(cli_help, optional_config=False, tasks=None):
    parser = new_tasks_flow_parser(cli_help, tasks)

    help_msg = 'config file for the procedure'
    if optional_config:
        parser.add_argument('procedure_config', metavar='procedure_config', type=str, help=help_msg, nargs='?')
    else:
        parser.add_argument('procedure_config', metavar='procedure_config', type=str, help=help_msg)

    return parser


def parse_args(parser, arguments: list = None):
    if arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(arguments)

    if args.workdir != '':
        os.chdir(args.workdir)

    return args


def schedule_cumulative_point(cluster: c.KubernetesCluster, point_method):
    _check_within_flow(cluster)

    point_fullname = point_method.__module__ + '.' + point_method.__qualname__

    if cluster.context['execution_arguments'].get('disable_cumulative_points', False):
        cluster.log.verbose('Method %s not scheduled - cumulative points disabled' % point_fullname)
        return

    if point_fullname in cluster.context['execution_arguments']['exclude_cumulative_points_methods']:
        cluster.log.verbose('Method %s not scheduled - it set to be excluded' % point_fullname)
        return

    scheduled_points = cluster.context.get('scheduled_cumulative_points', [])

    if point_method not in scheduled_points:
        scheduled_points.append(point_method)
        cluster.context['scheduled_cumulative_points'] = scheduled_points
        cluster.log.verbose('Method %s scheduled' % point_fullname)
    else:
        cluster.log.verbose('Method %s already scheduled' % point_fullname)


def proceed_cumulative_point(cluster: c.KubernetesCluster, points_list: dict,
                             point_task_name: Union[str, type(END_OF_TASKS)], force=False):
    _check_within_flow(cluster)

    if cluster.context['execution_arguments'].get('disable_cumulative_points', False):
        return

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


def init_tasks_flow(cluster):
    if 'proceeded_tasks' not in cluster.context:
        cluster.context['proceeded_tasks'] = []


def add_task_to_proceeded_list(cluster, task_path):
    if not is_task_completed(cluster, task_path):
        cluster.context['proceeded_tasks'].append(task_path)
        utils.dump_file(cluster, "\n".join(cluster.context['proceeded_tasks'])+"\n", 'finished_tasks')


def is_task_completed(cluster, task_path):
    _check_within_flow(cluster)
    return task_path in cluster.context['proceeded_tasks']


def _check_within_flow(cluster: c.KubernetesCluster, check=True):
    if check != ('proceeded_tasks' in cluster.context):
        raise NotImplementedError(f"The method is called {'not ' if check else ''}within tasks flow execution")
