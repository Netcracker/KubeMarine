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


from collections import OrderedDict

from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install
from kubemarine import system


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

    system.reboot_group(cluster.make_group_from_nodes(nodes),
                        try_graceful=cluster.procedure_inventory.get("graceful_reboot"))


tasks = OrderedDict({
    "reboot": reboot,
    "overview": install.overview,
})


class RebootAction(Action):
    def __init__(self):
        super().__init__('reboot')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for Kubernetes nodes graceful rebooting.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, optional_config=True, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='reboot')

    flow.run_actions(context, [RebootAction()])


if __name__ == '__main__':
    main()
