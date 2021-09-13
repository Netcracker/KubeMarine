#!/usr/bin/env python3

import argparse
import sys
from kubetool.core import utils
from kubetool.core.flow import load_inventory, create_context


def main(cli_arguments=None):

    if not cli_arguments:
        cli_arguments = sys.argv

    configfile_path = 'cluster.yaml'
    arguments = vars()

    kubetools_args = []
    remote_args = []

    if '--' not in cli_arguments:
        remote_args = cli_arguments
    else:
        split = False
        for argument in cli_arguments:
            if argument == '--':
                split = True
                continue
            if not split:
                kubetools_args.append(argument)
            else:
                remote_args.append(argument)

    if kubetools_args:
        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

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

        arguments = vars(parser.parse_args(kubetools_args))
        configfile_path = arguments.get('config')

    cluster = load_inventory(utils.get_resource_absolute_path(configfile_path, script_relative=False),
                             create_context({
                                 'disable_dump': True,
                                 'log': [
                                    ['stdout;level=error;colorize=true;correct_newlines=true']
                                 ]
                             }), silent=True)

    if kubetools_args:
        executor_lists = {
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
        executors_group = cluster.create_group_from_groups_nodes_names(executor_lists['group'], executor_lists['node'])
    else:
        executors_group = cluster.nodes['master'].get_any_member()

    if not executors_group or executors_group.nodes_amount() < 1:
        print('Failed to find any of specified nodes or groups')
        sys.exit(1)

    no_stream = arguments.get('no_stream')
    res = executors_group.sudo(" ".join(remote_args), hide=no_stream, warn=True)
    if no_stream:
        res.print()

    if res.is_any_failed():
        sys.exit(1)


if __name__ == '__main__':
    main()
