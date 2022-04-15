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

from kubemarine.core import flow
from kubemarine import deltas


def main(cli_arguments=None):
    cli_help = '''
        Script for automated update of the environment for the latest version of Kubemarine.

        How to use:
a
        '''

    parser = flow.new_parser(cli_help)
    parser.add_argument('--skip',
                        default='',
                        help='define comma-separated deltas to be skipped')

    parser.add_argument('--enforce',
                        default='',
                        help='define delta to be enforced (previous deltas will be skipped)')

    parser.add_argument('--non-interactive',
                        action='store_true',
                        help='disable any interactive actions and skip them')

    args = flow.parse_args(parser, cli_arguments)

    defined_skip = []
    defined_enforce = None

    if args.skip != '':
        defined_skip = args.skip.split(",")

    if args.enforce != '':
        defined_enforce = args.enforce

    context = flow.create_context(args, procedure="migrate_kubemarine")
    context["inventory_regenerate_required"] = True
    if args.non_interactive:
        context["noninteractive"] = True

    flow.run(
        {
            'migrate': lambda cluster: deltas.apply_deltas(cluster, defined_skip, defined_enforce)
        },
        [],
        [],
        args.config,
        context
    )


if __name__ == '__main__':
    main()
