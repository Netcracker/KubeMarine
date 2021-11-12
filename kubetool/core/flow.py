#!/usr/bin/env python3
# Copyright 2021 NetCracker Technology Corporation
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
import sys
import time
from copy import deepcopy

import yaml
import importlib

from kubetool.core import utils, cluster as c

DEFAULT_CLUSTER_OBJ = None


def run(tasks,
        tasks_filter,
        excluded_tasks,
        inventory_filepath,
        context,
        procedure_inventory_filepath=None,
        cumulative_points=None,
        print_final_message=True,
        cluster_obj=None):

    time_start = time.time()

    if cumulative_points is None:
        cumulative_points = {}

    if not context['execution_arguments'].get('disable_dump', True):
        utils.prepare_dump_directory(context['execution_arguments'].get('dump_location'),
                                     reset_directory=not context['execution_arguments'].get('disable_dump_cleanup', False))

    cluster = load_inventory(inventory_filepath, context, procedure_inventory_filepath=procedure_inventory_filepath,
                             cluster_obj=cluster_obj)

    cluster.log.debug("Excluded tasks:")
    filtered_tasks = filter_flow(tasks, tasks_filter, excluded_tasks)
    if filtered_tasks == tasks:
        cluster.log.debug("\tNo excluded tasks")

    if 'ansible_inventory_location' in cluster.context['execution_arguments']:
        utils.make_ansible_inventory(cluster.context['execution_arguments']['ansible_inventory_location'], cluster)

    if cluster.context.get('execution_arguments', {}).get('without_act', False):
        if cluster.context.get('inventory_regenerate_required', False) is True:
            utils.recreate_final_inventory_file(cluster)
        cluster.log.debug('\nFurther acting manually disabled')
        return cluster

    run_flow(filtered_tasks, cluster, cumulative_points)

    if cluster.context.get('inventory_regenerate_required', False) is True:
        utils.recreate_final_inventory_file(cluster)

    cluster.finish()

    time_end = time.time()

    if print_final_message:
        cluster.log.info("")
        cluster.log.info("SUCCESSFULLY FINISHED")
        cluster.log.info("Elapsed: "+utils.get_elapsed_string(time_start, time_end))

    return cluster


def create_empty_context(procedure=None):
    return {
        "execution_arguments": {},
        "proceeded_tasks": [],
        "nodes": {},
        'initial_procedure': procedure
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


def load_inventory(inventory_filepath, context, silent=False, procedure_inventory_filepath=None, cluster_obj=None):
    if not silent:
        print("Loading inventory file '%s'" % inventory_filepath)
    try:
        if cluster_obj is None:
            cluster_obj = DEFAULT_CLUSTER_OBJ
        if cluster_obj is None:
            cluster_obj = c.KubernetesCluster
        cluster = cluster_obj(inventory_filepath,
                              context,
                              procedure_inventory=procedure_inventory_filepath,
                              gather_facts=True)
        if not silent:
            cluster.log.debug("Inventory file loaded:")
            for role in cluster.roles:
                cluster.log.debug("  %s %i" % (role, len(cluster.ips[role])))
                for ip in cluster.ips[role]:
                    cluster.log.debug("    %s" % ip)
        return cluster
    except yaml.YAMLError as exc:
        utils.do_fail("Failed to load inventory file", exc)
    except Exception as exc:
        utils.do_fail("Failed to proceed inventory file", exc)


def filter_flow(tasks, tasks_filter, excluded_tasks, _task_path='', flow_changed=False):
    filtered = {}

    # Remove any whitespaces from filters
    map(str.strip, tasks_filter)
    map(str.strip, excluded_tasks)

    for task_name, task in tasks.items():
        if _task_path == '':
            __task_path = task_name
        else:
            __task_path = _task_path + "." + task_name

        allowed = True
        # if task_filter is not empty - smb specified filter argument
        if tasks_filter:
            allowed = False
            # Проверяем если итерируемый подпуть находится разрешенных путях. То есть проверяем есть ли
            # system_prepare.cri в разрешенном пути system_prepare.cri.docker
            for task_path in tasks_filter:
                if __task_path in task_path or task_path in __task_path:
                    allowed = True
                    # print("Allowed %s in %s" % (__task_path, task_path))

        if allowed and (not excluded_tasks or __task_path not in excluded_tasks):
            if callable(task):
                filtered[task_name] = task
            else:
                filtered_flow = filter_flow(task, tasks_filter, excluded_tasks, __task_path, flow_changed)
                if filter_flow is not {}:
                    filtered[task_name] = filtered_flow
        else:
            print("\t%s" % __task_path)

    return filtered


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


def new_parser(cli_help):

    parser = argparse.ArgumentParser(description=cli_help,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='enable the verbosity mode')

    parser.add_argument('-c', '--config',
                        default='cluster.yaml',
                        help='define main cluster configuration file')

    parser.add_argument('--without-act',
                        action='store_true',
                        help='prevent tasks to be executed')

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

    parser.add_argument('--log',
                        action='append',
                        nargs='*',
                        help='Logging options, can be specified multiple times')

    return parser


def schedule_cumulative_point(cluster, point_method):

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


def add_task_to_proceeded_list(cluster, task_path):
    if not is_task_completed(cluster, task_path):
        cluster.context['proceeded_tasks'].append(task_path)
        utils.dump_file(cluster, "\n".join(cluster.context['proceeded_tasks'])+"\n", 'finished_tasks')


def is_task_completed(cluster, task_path):
    return task_path in cluster.context['proceeded_tasks']
