import argparse
import json
import sys
from typing import List

import yaml

from kubemarine import plugins
from kubemarine.core import static, utils

HELP_DESCRIPTION = """\
Print supported configurations of 3rd-parties with versions compatibility.

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
    format_ = arguments['output']
    if format_ == 'yaml':
        print(yaml.safe_dump(cfg, sort_keys=False), end='')
    elif format_ == 'json':
        print(json.dumps(cfg, indent=4))


def main(cli_arguments: List[str] = None) -> None:
    if cli_arguments is None:
        cli_arguments = sys.argv[1:]

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     prog='config',
                                     description=HELP_DESCRIPTION)

    parser.add_argument('-o', '--output',
                        choices=['yaml', 'json'], default='yaml',
                        help='output format')

    arguments = vars(parser.parse_args(cli_arguments))

    cfg = make_config()
    print_config(cfg, arguments)


if __name__ == '__main__':
    main()
