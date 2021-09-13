import os
from abc import ABC, abstractmethod


class Environment(ABC):
    @property
    @abstractmethod
    def inventory(self) -> dict:
        pass

    @property
    @abstractmethod
    def globals(self) -> dict:
        pass

    @staticmethod
    def is_deploying_from_windows():
        return os.name == 'nt'
