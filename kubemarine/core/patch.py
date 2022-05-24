from abc import ABC, abstractmethod

from kubemarine.core.action import Action


class Patch(ABC):
    def __init__(self, identifier: str):
        self.identifier = identifier

    @property
    @abstractmethod
    def action(self) -> Action:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass
