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

from kubemarine.core.group import NodeGroup


def restrict_multi_os_group(fn: callable):
    """
    Method is an annotation that does not allow origin method to use different OS families in the same group.
    :param fn: Origin function to apply annotation validation to
    :return: Validation wrapper function
    """
    def wrapper(group: NodeGroup, *args, **kwargs):
        # TODO: walk through all nodes in *args, check isinstance NodeGroup and perform validation
        if group.is_multi_os():
            raise Exception(f'Method "{str(fn)}" do not supports multi-os group')
        return fn(group, *args, **kwargs)
    return wrapper


def restrict_empty_group(fn: callable):
    """
    Method is an annotation that prohibits passing empty groups to the function.
    :param fn: Origin function to apply annotation validation to
    :return: Validation wrapper function
    """
    def wrapper(group: NodeGroup, *args, **kwargs):
        # TODO: walk through all nodes in *args, check isinstance NodeGroup and perform validation
        if group.is_empty():
            raise Exception(f'Method "{str(fn)}" prohibits passing empty groups to it')
        return fn(group, *args, **kwargs)
    return wrapper
