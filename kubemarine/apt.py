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

import io
from typing import Union, Optional, List, Dict

from kubemarine.core import utils
from kubemarine.core.executor import RunnersResult, Token, Callback
from kubemarine.core.group import (
    NodeGroup, RunnersGroupResult, AbstractGroup, RunResult, DeferredGroup, GROUP_RUN_TYPE
)

DEBIAN_HEADERS = 'DEBIAN_FRONTEND=noninteractive '


def ls_repofiles(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('ls -la /etc/apt/sources.list.d')


def backup_repo(group: NodeGroup) -> Optional[RunnersGroupResult]:
    if not group.cluster.inventory['services']['packages']['package_manager']['replace-repositories']:
        group.cluster.log.debug("Skipped - repos replacement disabled in configuration")
        return None
    # all files in directory will be renamed: xxx.repo -> xxx.repo.bak
    # if there already any files with ".bak" extension, they should not be renamed to ".bak.bak"!
    return group.sudo("find /etc/apt/ -type f -name '*.list' | "
                      "sudo xargs -t -iNAME mv -bf NAME NAME.bak")


def add_repo(group: NodeGroup, repo_data: Union[List[str], Dict[str, dict], str]) -> RunnersGroupResult:
    create_repo_file(group, repo_data, get_repo_file_name())
    return group.sudo(DEBIAN_HEADERS + 'apt clean && sudo apt update')


def get_repo_file_name() -> str:
    return '/etc/apt/sources.list.d/predefined.list'


def create_repo_file(group: AbstractGroup[RunResult],
                     repo_data: Union[List[str], Dict[str, dict], str],
                     repo_file: str) -> None:
    # if repo_data is list, then convert it to string using join
    if isinstance(repo_data, list):
        repo_data_str = "\n".join(repo_data) + "\n"
    elif isinstance(repo_data, dict):
        raise Exception("Not supported repositories format for apt package manager")
    else:
        repo_data_str = utils.read_external(repo_data)

    repo_data_stream = io.StringIO(repo_data_str)
    group.put(repo_data_stream, repo_file, sudo=True)


def clean(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo(DEBIAN_HEADERS + "apt clean")


def get_install_cmd(include: Union[str, List[str]], exclude: Union[str, List[str]] = None) -> str:
    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt update && ' + \
              DEBIAN_HEADERS + 'sudo apt install -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    # apt fails to install (downgrade) package if it is already present and has higher version,
    # thus we do not need additional checks here (in contrast to yum)
    return command


def install(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None,
            callback: Callback = None) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to install')

    command = get_install_cmd(include, exclude)

    return group.sudo(command, callback=callback)


def remove(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None, exclude: Union[str, List[str]] = None,
           warn: bool = False, hide: bool = True) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt purge -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, warn=warn, hide=hide)


def upgrade(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = DEBIAN_HEADERS + 'apt update && ' + \
              DEBIAN_HEADERS + 'sudo apt upgrade -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command)


def no_changes_found(action: str, result: RunnersResult) -> bool:
    if action not in ('install', 'upgrade', 'remove'):
        raise Exception(f"Unknown action {action}")
    return "0 upgraded, 0 newly installed, 0 to remove" in result.stdout


def search(group: DeferredGroup, package: str, callback: Callback = None) -> Token:
    if package is None:
        raise Exception('You must specify package to search')
    command = DEBIAN_HEADERS + 'apt show %s' % package

    return group.sudo(command, warn=True, callback=callback)
