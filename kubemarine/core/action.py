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

from abc import ABC, abstractmethod

from kubemarine.core.resources import DynamicResources


class Action(ABC):
    """Base class for doing some work based on provided DynamicResources"""

    def __init__(self, identifier: str, recreate_inventory=False):
        """
        Constructor of Action to be invoked from derived classes.

        :param identifier action identifier, which will be preserved on nodes
                          if the action is successfully performed.
        :param recreate_inventory specifies if inventory should be recreated after the action succeeds.
        """

        self.identifier = identifier
        self.recreate_inventory = recreate_inventory

    @abstractmethod
    def run(self, res: DynamicResources):
        """
        Do some work based on provided DynamicResources.

        Avoid direct exiting in case of exceptions (for example using utils.do_fail),
        unless it is the only action being executed.
        Otherwise, correct exception handling will not be performed.
        """
        pass

    def prepare_context(self, context: dict):
        """Called first before any work with the action"""
        return
