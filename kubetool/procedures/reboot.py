#!/usr/bin/env python3

from collections import OrderedDict

from kubetool.core import flow
from kubetool.procedures import install
from kubetool import system


def reboot(cluster):
    if cluster.context.get('initial_procedure') != 'reboot':
        raise ImportError('Invalid reboot.py usage, please use system.reboot_nodes')

    if not cluster.procedure_inventory.get("nodes"):
        cluster.log.verbose('No nodes defined in procedure: all nodes will be rebooted')
    else:
        cluster.log.verbose('There are nodes defined in procedure: only defined will be rebooted')

    nodes = []

    cluster.log.verbose('The following nodes will be rebooted:')
    for node in cluster.procedure_inventory.get("nodes", cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True)):
        nodes.append(node['name'])
        cluster.log.verbose('  - ' + node['name'])

    system.reboot_nodes(cluster.make_group_from_nodes(nodes),
                        try_graceful=cluster.procedure_inventory.get("graceful_reboot"))


tasks = OrderedDict({
    "reboot": reboot,
    "overview": install.overview,
})


def main(cli_arguments=None):
    cli_help = '''
    Script for Kubernetes nodes graceful rebooting.

    How to use:

    '''

    parser = flow.new_parser(cli_help)
    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('procedure_config', nargs='?', metavar='procedure_config', type=str,
                        help='config file for reboot procedure')

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

    context = flow.create_context(args, procedure='reboot')
    context['inventory_regenerate_required'] = False

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        procedure_inventory_filepath=args.procedure_config,
        cumulative_points=install.cumulative_points
    )


if __name__ == '__main__':
    main()
