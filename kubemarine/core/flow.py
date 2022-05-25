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
import sys
import time
from copy import deepcopy
from typing import Type, Optional, List

import importlib

from kubemarine.core import utils, cluster as c, action, resources as res, errors

DEFAULT_CLUSTER_OBJ: Optional[Type[c.KubernetesCluster]] = None


def run_actions(context: dict, actions: List[action.Action],
                resources: res.DynamicResources = None,
                print_final_message=True, silent=False) -> Optional[c.KubernetesCluster]:
    """
    Runs actions one by one, recreates inventory when necessary,
    managing such resources as cluster object and raw inventory.

    For each initialized cluster object, preserves inventory if any action is succeeded.
    """
    time_start = time.time()

    args: dict = context['execution_arguments']
    if not args.get('disable_dump', True):
        utils.prepare_dump_directory(args.get('dump_location'),
                                     reset_directory=not args.get('disable_dump_cleanup', False))

    if resources is None:
        resources = res.DynamicResources(context, silent)
    log = resources.logger()

    successfully_performed = []
    last_cluster = None
    for act in actions:
        act.prepare_context(resources.context)

        if not successfully_performed:
            # first action in group
            if resources.inventory_filepath:
                with open(resources.inventory_filepath, "r") as stream:
                    utils.dump_file(context, stream, "cluster_initial.yaml")

            if resources.procedure_inventory_filepath:
                with open(resources.procedure_inventory_filepath, "r") as stream:
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
                with open(resources.inventory_filepath, "r") as stream:
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

    if print_final_message:
        log.info("")
        log.info("SUCCESSFULLY FINISHED")
        log.info("Elapsed: " + utils.get_elapsed_string(time_start, time_end))

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


def run_tasks(resources: res.DynamicResources, tasks, cumulative_points=None):
    """
    Filters and runs tasks and immediately exits in case any task fails.
    It is preferable to use the method only in case the only action is executed.
    """

    if cumulative_points is None:
        cumulative_points = {}

    args: dict = resources.context['execution_arguments']

    tasks_filter = [] if not args['tasks'] else args['tasks'].split(",")
    excluded_tasks = [] if not args['exclude'] else args['exclude'].split(",")

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
    run_flow(filtered_tasks, cluster, cumulative_points)


def create_empty_context(procedure=None):
    return {
        "execution_arguments": {},
        "nodes": {},
        'initial_procedure': procedure,
        'preserve_inventory': True,
        'runtime_vars': {}
    }


def create_context(execution_arguments, procedure=None):

    if isinstance(execution_arguments, argparse.Namespace):
        execution_arguments = vars(execution_arguments)

    context = create_empty_context(procedure=procedure)
    context["execution_arguments"] = deepcopy(execution_arguments)

    if context['execution_arguments'].get('exclude_cumulative_points_methods', '').strip() != '':
        context['execution_arguments']['exclude_cumulative_points_methods'] = \
            context['execution_arguments']['exclude_cumulative_points_methods'].strip().split(",")
        # print('The following cumulative points methods are marked for exclusion: [ %s ]' %
        #               ', '.join(context['execution_arguments']['exclude_cumulative_points_methods']))
    else:
        context['execution_arguments']['exclude_cumulative_points_methods'] = []

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
                    # print("Allowed %s in %s" % (__task_path, task_path))

        if allowed and __task_path not in excluded_tasks:
            if callable(task):
                filtered[task_name] = task
                final_list.append(".".join(__task_path))
            else:
                filtered_flow, _final_list = _filter_flow_internal(task, tasks_filter, excluded_tasks, __task_path)
                # there is something to execute in subtree
                if filtered_flow:
                    filtered[task_name] = filtered_flow
                    final_list += _final_list
        else:
            print("\t%s" % ".".join(__task_path))

    return filtered, final_list


def run_flow(tasks, cluster, cumulative_points, _task_path=''):
    for task_name, task in tasks.items():

        if _task_path == '':
            __task_path = task_name
        else:
            __task_path = _task_path + "." + task_name

        proceed_cumulative_point(cluster, cumulative_points, __task_path)

        if callable(task):
            cluster.log.info("*** TASK %s ***" % __task_path)
            try:
                task(cluster)
                add_task_to_proceeded_list(cluster, __task_path)
            except Exception as exc:
                utils.do_fail("TASK FAILED %s" % __task_path, exc,
                              hint=cluster.globals['error_handling']['failure_message'] % (sys.argv[0], __task_path),
                              log=cluster.log)
        else:
            run_flow(task, cluster, cumulative_points, __task_path)


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

    return parser


def new_tasks_flow_parser(cli_help):
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

    return parser


def new_procedure_parser(cli_help):
    parser = new_tasks_flow_parser(cli_help)

    parser.add_argument('procedure_config', metavar='procedure_config', type=str,
                        help='config file for the procedure')

    return parser


def parse_args(parser, arguments: None):
    if arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(arguments)

    if args.workdir != '':
        os.chdir(args.workdir)

    return args


def schedule_cumulative_point(cluster, point_method):
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


def proceed_cumulative_point(cluster, points_list, point_task_path):
    _check_within_flow(cluster)

    if cluster.context['execution_arguments'].get('disable_cumulative_points', False):
        return

    scheduled_methods = cluster.context.get('scheduled_cumulative_points', [])

    results = {}
    for point_method_fullname, points_tasks_paths in points_list.items():
        if point_task_path in points_tasks_paths:

            if cluster.context['execution_arguments'].get('force_cumulative_points', False):
                cluster.log.verbose('Method %s will be forcibly executed' % point_method_fullname)
            else:
                if point_method_fullname not in [x.__module__+'.'+x.__qualname__ for x in scheduled_methods]:
                    cluster.log.verbose('Method %s not scheduled - cumulative point call skipped' % point_method_fullname)
                    continue

            cluster.log.info("*** CUMULATIVE POINT %s ***" % point_method_fullname)

            mod_name, func_name = point_method_fullname.rsplit('.', 1)
            mod = importlib.import_module(mod_name)
            func = getattr(mod, func_name)

            call_result = cluster.nodes["all"].get_new_nodes_or_self().call(func)
            cluster.context['scheduled_cumulative_points'].remove(func)
            results[point_method_fullname] = call_result

    return results


def init_tasks_flow(cluster):
    _check_within_flow(cluster, False)
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
