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

import fabric

from kubemarine.core import utils
from kubemarine.core.group import NodeGroupResult, NodeGroup


def ls_repofiles(group, **kwargs):
    return group.sudo('ls -la /etc/yum.repos.d', **kwargs)


def backup_repo(group, repo_filename="*", **kwargs):
    if not group.cluster.inventory['services']['packages']['package_manager']['replace-repositories']:
        group.cluster.log.debug("Skipped - repos replacement disabled in configuration")
        return
    # all files in directory will be renamed: xxx.repo -> xxx.repo.bak
    # if there already any files with ".bak" extension, they should not be renamed to ".bak.bak"!
    return group.sudo("find /etc/yum.repos.d/ -type f -name '%s.repo' | "
                      "sudo xargs -t -iNAME mv -bf NAME NAME.bak" % repo_filename, **kwargs)


def add_repo(group, repo_data="", repo_filename="predefined", **kwargs):
    create_repo_file(group, repo_data, get_repo_file_name(repo_filename))
    return group.sudo('yum clean all && sudo yum updateinfo', **kwargs)


def get_repo_file_name(repo_filename="predefined"):
    return '/etc/yum.repos.d/%s.repo' % repo_filename


def create_repo_file(group, repo_data, repo_file):
    # if repo_data is dict, then convert it to string with config inside
    if isinstance(repo_data, dict):
        config = configparser.ConfigParser()
        for repo_id, data in repo_data.items():
            config[repo_id] = data
        repo_data = io.StringIO()
        config.write(repo_data)
    else:
        repo_data = io.StringIO(utils.read_external(repo_data))
    group.put(repo_data, repo_file, sudo=True)


def clean(group, mode="all", **kwargs):
    return group.sudo("yum clean %s" % mode, **kwargs)


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


def install(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to install')

    command = get_install_cmd(include, exclude)

    return group.sudo(command, **kwargs)


def remove(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to remove')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum remove -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)


def upgrade(group, include=None, exclude=None, **kwargs):
    if include is None:
        raise Exception('You must specify included packages to upgrade')

    if isinstance(include, list):
        include = ' '.join(include)
    command = 'yum upgrade -y %s' % include

    if exclude is not None:
        if isinstance(exclude, list):
            exclude = ','.join(exclude)
        command += ' --exclude=%s' % exclude

    return group.sudo(command, **kwargs)


def no_changes_found(action: callable, result: fabric.runners.Result) -> bool:
    if action is install:
        return "Nothing to do" in result.stdout
    elif action is upgrade:
        return "No packages marked for update" in result.stdout
    elif action is remove:
        return "No Packages marked for removal" in result.stdout
    else:
        raise Exception(f"Unknown action {action}")


def search(group: NodeGroup, package: str, **kwargs) -> NodeGroupResult:
    if package is None:
        raise Exception('You must specify package to search')
    command = 'yum list %s || echo "Package is unavailable"' % package
    return group.sudo(command, **kwargs)