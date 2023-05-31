import os
from typing import Iterator, Mapping


class Environ(Mapping[str, str]):
    """
    Read-only view of os.environ.
    """

    def __getitem__(self, name: str) -> str:
        # check presence of the variable and throw KeyError if necessary
        return os.environ[name]

    def __len__(self) -> int:
        return len(os.environ)

    def __iter__(self) -> Iterator[str]:
        return iter(os.environ)

    __slots__ = []
