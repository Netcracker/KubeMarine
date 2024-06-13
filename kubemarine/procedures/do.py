#!/usr/bin/env python3
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
import sys
from typing import List, Dict, Any

from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources

HELP_DESCRIPTION = """
Script for executing shell command
    
additional arguments:
    shell_command       command to execute on nodes
"""


class CLIAction(Action):
    def __init__(self, context: dict) -> None:
        super().__init__('do')
        self.do_args: Dict[str, Any] = context['do_arguments']
        self.remote_args: List[str] = context['remote_arguments']

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster(EnrichmentStage.LIGHT)
        executors_group = get_executors_group(cluster, self.do_args)
        if executors_group.is_empty():
            print('Failed to find any of specified nodes or groups')  # pylint: disable=bad-builtin
            sys.exit(1)

        no_stream: bool = self.do_args['no_stream']
        pty: bool = self.do_args['pty']
        result = executors_group.sudo(" ".join(self.remote_args), hide=no_stream, pty=pty, warn=True)
        if no_stream:
            print(result)  # pylint: disable=bad-builtin

        if result.is_any_failed():
            sys.exit(1)


def create_context(cli_arguments: List[str] = None) -> dict:
    if cli_arguments is None:
        cli_arguments = sys.argv[1:]

    if '--' in cli_arguments:
        kubemarine_args = cli_arguments[:cli_arguments.index('--')]
        remote_args = cli_arguments[cli_arguments.index('--') + 1:]
    else:
        kubemarine_args = cli_arguments
        remote_args = []

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     prog='do',
                                     description=HELP_DESCRIPTION,
                                     usage='%(prog)s [-h] [-c CONFIG] [-n NODE] [-g GROUP] [--no_stream] -- shell_command')

    parser.add_argument('-c', '--config',
                            default='cluster.yaml',
                            help='define main cluster configuration file')

    parser.add_argument('-n', '--node',
                            help='node(s) name to execute on, can be combined with groups')

    parser.add_argument('-g', '--group',
                            help='group(s) name to execute on, can be combined with nodes')

    parser.add_argument('--no_stream',
                            action='store_true',
                            help='do not stream all remote results in real-time, show node names')

    parser.add_argument('-p', '--pty',
                        action='store_true',
                        help='Use a pty when executing shell commands.')

    arguments = vars(parser.parse_args(kubemarine_args))
    configfile_path = arguments.get('config')

    context = flow.create_empty_context({
        'disable_dump': True,
        'dump_location': '.',
        'disable_dump_cleanup': True,
        'log': [
            ['stdout;level=error;colorize=true;correct_newlines=true']
        ],
        'config': configfile_path,
    }, procedure='do')
    context['preserve_inventory'] = False
    context['make_finalized_inventory'] = False
    context['load_inventory_silent'] = True

    context['do_arguments'] = arguments
    context['remote_arguments'] = remote_args

    return context


def get_executors_group(cluster: KubernetesCluster, arguments: dict) -> NodeGroup:
    if arguments.get('node', None) is not None or arguments.get('group', None) is not None:
        executors: Dict[str, List[str]] = {
            'node': [],
            'group': []
        }
        for executors_type, executor_lists in executors.items():
            executors_str = arguments.get(executors_type)
            if executors_str:
                if "," in executors_str:
                    for executor_name in executors_str.split(','):
                        executor_lists.append(executor_name.strip())
                else:
                    executor_lists.append(executors_str.strip())
        return cluster.create_group_from_groups_nodes_names(executors['group'], executors['node'])
    else:
        # 'master' role is not deleted due to longer inventory compatibility contract for `do`.
        return cluster.make_group_from_roles(['control-plane', 'master']).get_any_member()


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    action = CLIAction(context)
    flow.ActionsFlow([action]).run_flow(context, print_summary=False)


if __name__ == '__main__':
    main()
