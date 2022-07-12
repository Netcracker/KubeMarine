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

import kubemarine.patches
from kubemarine.core import flow


def main(cli_arguments=None):
    cli_help = '''
    Script for automated update of the environment for the current version of Kubemarine.

    How to use:

    '''

    parser = flow.new_common_parser(cli_help)
    parser.add_argument('--force-skip', dest='skip', metavar='SKIP',
                        default='',
                        help='define comma-separated patches to skip')

    parser.add_argument('--force-apply', dest='apply', metavar='APPLY',
                        default='',
                        help='define explicit comma-separated set of patches to apply')

    parser.add_argument('--list',
                        action='store_true',
                        help='list all patches')

    parser.add_argument('--describe', metavar='PATCH',
                        help='describe the specified patch')

    context = flow.create_context(parser, cli_arguments, procedure="migrate_kubemarine")
    args = context['execution_arguments']

    patches = kubemarine.patches.patches
    patch_ids = [patch.identifier for patch in patches]

    if args['list']:
        if patch_ids:
            print("Available patches list:")
            for patch_id in patch_ids:
                print(patch_id)
        else:
            print("No patches available.")
        exit(0)

    if args['describe']:
        for patch in patches:
            if patch.identifier == args['describe']:
                print(patch.description)
                exit(0)
        print(f"Unknown patch '{args['describe']}'")
        exit(1)

    skip = [] if not args['skip'] else args['skip'].split(",")
    apply = [] if not args['apply'] else args['apply'].split(",")

    if apply and (set(apply) - set(patch_ids)):
        print(f"Unknown patches {list(set(apply) - set(patch_ids))}")
        exit(1)

    if skip and (set(skip) - set(patch_ids)):
        print(f"Unknown patches {list(set(skip) - set(patch_ids))}")
        exit(1)

    if apply:
        positions = [patch_ids.index(apply_id) for apply_id in apply]
        if not all(positions[i] < positions[i + 1] for i in range(len(positions) - 1)):
            print("Incorrect order of patches to apply. See --list for correct order of patches.")
            exit(1)

    actions = []
    for patch in patches:
        if apply:
            if patch.identifier in apply:
                actions.append(patch.action)
        elif skip:
            if patch.identifier not in skip:
                actions.append(patch.action)
        else:
            actions.append(patch.action)

    if not actions:
        print("No patches to apply")
        exit(0)
    flow.run_actions(context, actions)


if __name__ == '__main__':
    main()
