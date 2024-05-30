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

import configparser
import io
from typing import Union, Optional, List, Dict

from kubemarine.core import utils
from kubemarine.core.executor import RunnersResult, Token, Callback
from kubemarine.core.group import (
    NodeGroup, RunnersGroupResult, AbstractGroup, RunResult, DeferredGroup, GROUP_RUN_TYPE
)


def ls_repofiles(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('ls -la /etc/yum.repos.d')


def backup_repo(group: NodeGroup) -> Optional[RunnersGroupResult]:
    if not group.cluster.inventory['services']['packages']['package_manager']['replace-repositories']:
        group.cluster.log.debug("Skipped - repos replacement disabled in configuration")
        return None
    # all files in directory will be renamed: xxx.repo -> xxx.repo.bak
    # if there already any files with ".bak" extension, they should not be renamed to ".bak.bak"!
    return group.sudo("find /etc/yum.repos.d/ -type f -name '*.repo' | "
                      "sudo xargs -t -iNAME mv -bf NAME NAME.bak")


def add_repo(group: NodeGroup, repo_data: Union[List[str], Dict[str, dict], str]) -> RunnersGroupResult:
    create_repo_file(group, repo_data, get_repo_file_name())
    return group.sudo('yum clean all && sudo yum updateinfo -d1', pty=True)


def get_repo_file_name() -> str:
    return '/etc/yum.repos.d/predefined.repo'


def create_repo_file(group: AbstractGroup[RunResult],
                     repo_data: Union[List[str], Dict[str, dict], str],
                     repo_file: str) -> None:
    # if repo_data is dict, then convert it to string with config inside
    if isinstance(repo_data, dict):
        config = configparser.ConfigParser()
        for repo_id, data in repo_data.items():
            config[repo_id] = data
        repo_data_stream = io.StringIO()
        config.write(repo_data_stream)
    elif isinstance(repo_data, list):
        raise Exception("Not supported repositories format for yum package manager")
    else:
        repo_data_stream = io.StringIO(utils.read_external(repo_data))

    group.put(repo_data_stream, repo_file, sudo=True)


def clean(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo("yum clean all", pty=True)


def get_install_cmd(include: Union[str, List[str]], exclude: Union[str, List[str]] = None) -> str:
    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum install -y -d1 --color=never %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude
    command += f"; PACKAGES=$(rpm -q {include}); " \
               f"if [ $? != 0 ]; then echo \"$PACKAGES\" | grep 'is not installed'; " \
               f"echo \"Failed to check version for some packages. " \
               f"Make sure packages are not already installed with higher versions. " \
               f"Also, make sure user-defined packages have rpm-compatible names. \"; exit 1; fi "

    return command


def install(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None,
            pty: bool = False, callback: Callback = None) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to install')

    command = get_install_cmd(include, exclude)

    return group.sudo(command, pty=pty, callback=callback)


def remove(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
           exclude: Union[str, List[str]] = None,
           warn: bool = False, hide: bool = True, pty: bool = False) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum remove -y -d1 --color=never %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, warn=warn, hide=hide, pty=pty)


def upgrade(group: AbstractGroup[GROUP_RUN_TYPE], include: Union[str, List[str]] = None,
            exclude: Union[str, List[str]] = None,
            pty: bool = False) -> GROUP_RUN_TYPE:
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum upgrade -y -d1 --color=never %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, pty=pty)


def no_changes_found(action: str, result: RunnersResult) -> bool:
    if action not in ('install', 'upgrade', 'remove'):
        raise Exception(f"Unknown action {action}")

    output = result.stdout.rstrip('\n')
    if "Nothing to do." in output:
        return True
    # Remove next checks after `rhel` (version 7) OS family support stop.
    if action == 'install' and all(
            'already installed and latest version' in line
            for line in output.split('\n')):
        return True
    if action == 'upgrade' and not output or all(
            'No Match for argument' in line
            for line in output.split('\n')):
        return True
    if action == 'remove' and all(
            'No Match for argument' in line
            for line in output.split('\n')):
        return True

    return False


def search(group: DeferredGroup, package: str, callback: Callback = None) -> Token:
    if package is None:
        raise Exception('You must specify package to search')
    command = 'yum list -d1 %s' % package

    return group.sudo(command, pty=True, warn=True, callback=callback)
