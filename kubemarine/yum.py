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
from typing import Union, Callable, Optional

from kubemarine.core import utils
from kubemarine.core.executor import RunnersResult, is_executor_active, Token
from kubemarine.core.group import NodeGroup, RunnersGroupResult


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


def add_repo(group: NodeGroup, repo_data="", repo_filename="predefined") -> RunnersGroupResult:
    create_repo_file(group, repo_data, get_repo_file_name(repo_filename))
    return group.sudo('yum clean all && sudo yum updateinfo')


def get_repo_file_name(repo_filename="predefined") -> str:
    return '/etc/yum.repos.d/%s.repo' % repo_filename


def create_repo_file(group: NodeGroup, repo_data, repo_file) -> None:
    # if repo_data is dict, then convert it to string with config inside
    if isinstance(repo_data, dict):
        config = configparser.ConfigParser()
        for repo_id, data in repo_data.items():
            config[repo_id] = data
        repo_data = io.StringIO()
        config.write(repo_data)
    else:
        repo_data = io.StringIO(utils.read_external(repo_data))

    if is_executor_active():
        group.defer().put(repo_data, repo_file, sudo=True)
    else:
        group.put(repo_data, repo_file, sudo=True)


def clean(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo("yum clean all")


def get_install_cmd(include: str or list, exclude=None) -> str:
    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum install -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude
    command += f"; rpm -q {include}; if [ $? != 0 ]; then echo \"Failed to check version for some packages. " \
               f"Make sure packages are not already installed with higher versions. " \
               f"Also, make sure user-defined packages have rpm-compatible names. \"; exit 1; fi "

    return command


def install(group: NodeGroup, include=None, exclude=None) -> Union[Token, RunnersGroupResult]:
    if include is None:
        raise Exception('You must specify included packages to install')

    command = get_install_cmd(include, exclude)

    if is_executor_active():
        return group.defer().sudo(command)
    else:
        return group.sudo(command)


def remove(group: NodeGroup, include=None, exclude=None, warn=False, hide=True) -> RunnersGroupResult:
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum remove -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, warn=warn, hide=hide)


def upgrade(group: NodeGroup, include=None, exclude=None) -> RunnersGroupResult:
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum upgrade -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command)


def no_changes_found(action: Callable, result: RunnersResult) -> bool:
    if action is install:
        return "Nothing to do" in result.stdout
    elif action is upgrade:
        return "No packages marked for update" in result.stdout
    elif action is remove:
        return "No Packages marked for removal" in result.stdout
    else:
        raise Exception(f"Unknown action {action}")


def search(group: NodeGroup, package: str) -> Token:
    if package is None:
        raise Exception('You must specify package to search')
    command = 'yum list %s || echo "Package is unavailable"' % package

    return group.defer().sudo(command)
