#!/usr/bin/env python3

from collections import OrderedDict

from kubetool import psp
from kubetool.core import flow

tasks = OrderedDict({
    "delete_custom": psp.delete_custom_task,
    "add_custom": psp.add_custom_task,
    "reconfigure_oob": psp.reconfigure_oob_task,
    "reconfigure_plugin": psp.reconfigure_plugin_task,
    "restart_pods": psp.restart_pods_task
})


def main(cli_arguments=None):

    cli_help = '''
    Script for managing psp on existing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_parser(cli_help)
    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('procedure_config', metavar='procedure_config', type=str,
                        help='config file for add_node procedure')

    if cli_arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    context = flow.create_context(args, procedure='manage_psp')
    context['inventory_regenerate_required'] = True

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        procedure_inventory_filepath=args.procedure_config,
    )


if __name__ == '__main__':
    main()
