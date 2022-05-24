from abc import ABC, abstractmethod

from kubemarine.core import resources


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
    def run(self, res: 'resources.DynamicResources'):
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
