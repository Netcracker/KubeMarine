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

from kubemarine import admission
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources

tasks = OrderedDict({
    "check_inventory": admission.check_inventory,
    "delete_default_pss": admission.delete_default_pss,
    "apply_default_pss": admission.apply_default_pss,
    "restart_pods": admission.restart_pods_task
})


class PSSAction(Action):
    def __init__(self):
        super().__init__('manage pss', recreate_inventory=True)

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def main(cli_arguments=None):

    cli_help = '''
    Script for managing pss on existing Kubernetes cluster.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure='manage_pss')

    flow.run_actions(context, [PSSAction()])


if __name__ == '__main__':
    main()
