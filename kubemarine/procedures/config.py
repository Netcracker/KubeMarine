# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import sys
from typing import List

import yaml

from kubemarine import plugins
from kubemarine.core import static

HELP_DESCRIPTION = """\
Print the supported k8s versions with the respective configurations of third-parties.

How to use:

"""


def make_config() -> dict:
    kubernetes_versions: dict = {}
    for version, compatibility_map in static.KUBERNETES_VERSIONS['compatibility_map'].items():
        kubernetes_version = kubernetes_versions.setdefault(version, {})

        plugins_ = plugins.oob_plugins
        thirdparties_ = ['crictl']

        for software, software_version in compatibility_map.items():
            if software in plugins_:
                kubernetes_version.setdefault('plugins', {}) \
                    .setdefault(software, {})['version'] = software_version

            if software in thirdparties_:
                kubernetes_version.setdefault('thirdparties', {}) \
                    .setdefault(software, {})['version'] = software_version

    return {'kubernetes': kubernetes_versions}


def print_config(cfg: dict, arguments: dict) -> None:
    # pylint: disable=bad-builtin

    format_ = arguments['output']
    if format_ == 'yaml':
        print(yaml.safe_dump(cfg, sort_keys=False), end='')
    elif format_ == 'json':
        print(json.dumps(cfg, indent=4))


def create_context(cli_arguments: List[str] = None) -> dict:
    if cli_arguments is None:
        cli_arguments = sys.argv[1:]

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     prog='config',
                                     description=HELP_DESCRIPTION)

    parser.add_argument('-o', '--output',
                        choices=['yaml', 'json'], default='yaml',
                        help='output format')

    arguments = vars(parser.parse_args(cli_arguments))
    return {'config_arguments': arguments}


def main(cli_arguments: List[str] = None) -> None:
    arguments = create_context(cli_arguments)['config_arguments']
    cfg = make_config()
    print_config(cfg, arguments)


if __name__ == '__main__':
    main()
