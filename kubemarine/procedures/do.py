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
from typing import Callable, List, Dict

from kubemarine.core import flow, resources
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources

HELP_DESCRIPTION = """
Script for executing shell command
    
additional arguments:
    shell_command       command to execute on nodes
"""

class CLIAction(Action):
    def __init__(self, node_group_provider: Callable[[KubernetesCluster], NodeGroup],
                 remote_args: List[str], no_stream: bool) -> None:
        super().__init__('do')
        self.node_group_provider = node_group_provider
        self.remote_args = remote_args
        self.no_stream = no_stream

    def run(self, res: DynamicResources) -> None:
        cluster = res.cluster()
        executors_group = self.node_group_provider(cluster)
        if executors_group.is_empty():
            print('Failed to find any of specified nodes or groups')
            sys.exit(1)

        result = executors_group.sudo(" ".join(self.remote_args), hide=self.no_stream, warn=True)
        if self.no_stream:
            cluster.log.debug(result)

        if result.is_any_failed():
            sys.exit(1)

        sys.exit(0)


def main(cli_arguments: List[str] = None) -> None:

    if not cli_arguments:
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

    arguments = vars(parser.parse_args(kubemarine_args))
    configfile_path = arguments.get('config')

    context = flow.create_empty_context({
        'disable_dump': True,
        'log': [
            ['stdout;level=error;colorize=true;correct_newlines=true']
        ],
        'config': configfile_path,
    })
    context['preserve_inventory'] = False

    def node_group_provider(cluster: KubernetesCluster) -> NodeGroup:
        if arguments.get('node', None) is not None or arguments.get('group', None) is not None:
            executor_lists: Dict[str, List[str]] = {
                    'node': [],
                    'group': []
            }
            for executors_type in executor_lists.keys():
                executors_str = arguments.get(executors_type)
                if executors_str:
                    if "," in executors_str:
                        for executor_name in executors_str.split(','):
                            executor_lists[executors_type].append(executor_name.strip())
                    else:
                        executor_lists[executors_type].append(executors_str.strip())
            return cluster.create_group_from_groups_nodes_names(executor_lists['group'], executor_lists['node'])
        else:
            return cluster.nodes['control-plane'].get_any_member()

    no_stream: bool = arguments['no_stream']
    action = CLIAction(node_group_provider, remote_args, no_stream)
    res = resources.DynamicResources(context, silent=True)
    flow.ActionsFlow([action]).run_flow(res, print_summary=False)


if __name__ == '__main__':
    main()
