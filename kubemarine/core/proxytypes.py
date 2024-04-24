import json
from abc import ABC, abstractmethod
from typing import Any, Union, Sequence, List, Iterator, Mapping, Type, Dict

import yaml

Index = Union[str, int]
Primitive = Union[str, int, bool, float]


class Proxy(ABC):
    def __repr__(self) -> str:
        return repr(self._KM_materialize())

    @abstractmethod
    def _KM_materialize(self) -> Any: ...


class DelegatingProxy(Proxy, ABC):
    @abstractmethod
    def _KM_unsafe(self) -> Union[dict, list]: ...

    @abstractmethod
    def _KM__getitem__(self, index: Index) -> Union[Primitive, Proxy]: ...


class MappingProxy(DelegatingProxy, Mapping[str, Any], ABC):
    def __getitem__(self, k: str) -> Any:
        return self._KM__getitem__(k)

    def __len__(self) -> int:
        return len(self._KM_unsafe())

    def __iter__(self) -> Iterator[str]:
        return iter(self._KM_unsafe())

    def _KM_materialize(self) -> Any:
        return dict(self)


class SequenceProxy(DelegatingProxy, Sequence[Any], ABC):
    def __getitem__(self, index: Union[int, slice]) -> Any:
        if isinstance(index, slice):
            indexes = list(range(len(self)))[index]
            return SliceProxy(self, indexes)

        return self._KM__getitem__(index)

    def __len__(self) -> int:
        return len(self._KM_unsafe())

    def _KM_materialize(self) -> Any:
        return list(self)


class SliceProxy(Proxy, Sequence[Any]):
    def __init__(self, sequence: SequenceProxy, indexes: List[int]):
        self._KM_sequence = sequence
        self._KM_indexes = indexes

    def __getitem__(self, index: Union[int, slice]) -> Any:
        if isinstance(index, slice):
            indexes = self._KM_indexes[index]
            return SliceProxy(self._KM_sequence, indexes)

        return self._KM_sequence[self._KM_indexes[index]]

    def __len__(self) -> int:
        return len(self._KM_indexes)

    def _KM_materialize(self) -> Any:
        return list(self)


class Node:
    def __init__(self, delegate: Union[dict, list]):
        self.delegate = delegate

    def descend(self, index: Index) -> Union[Primitive, 'Node']:
        val: Union[Primitive, list, dict] = self.delegate[index]  # type: ignore[index]
        if isinstance(val, (list, dict)):
            return self._child(index, val)

        return val

    def _child(self, index: Index, val: Union[list, dict]) -> 'Node':
        return self._child_type(index)(val)

    def _child_type(self, _: Index) -> Type['Node']:
        return Node


class MutableNode(Node, ABC):
    def descend(self, index: Index) -> Union[Primitive, Node]:
        child = super().descend(index)
        if isinstance(child, Node):
            return child

        val = self._convert(index, child)
        self.delegate[index] = val  # type: ignore[index]

        return val

    @abstractmethod
    def _convert(self, index: Index, val: Primitive) -> Primitive: ...

    def _child_type(self, _: Index) -> Type[Node]:
        return MutableNode


class NodeProxy(DelegatingProxy, ABC):
    def __init__(self, node: Node):
        self._KM_node = node
        self._KM_cached: Dict[Index, Union[Primitive, Proxy]] = {}

    def _KM_unsafe(self) -> Union[dict, list]:
        return self._KM_node.delegate

    def _KM__getitem__(self, index: Index) -> Union[Primitive, Proxy]:
        if index not in self._KM_cached:
            child = self._KM_node.descend(index)
            val = ((NodeMapping(child) if isinstance(child.delegate, dict) else NodeSequence(child))
                   if isinstance(child, Node)
                   else child)

            self._KM_cached[index] = val
            return val

        return self._KM_cached[index]


class NodeMapping(NodeProxy, MappingProxy):
    pass


class NodeSequence(NodeProxy, SequenceProxy):
    pass


class ProxyJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, Proxy):
            return o._KM_materialize()  # pylint: disable=protected-access

        return super().default(o)


def proxy_representer(dumper: yaml.Dumper, data: Proxy) -> Any:
    val = data._KM_materialize()  # pylint: disable=protected-access
    return dumper.yaml_representers[type(val)](dumper, val)


class ProxyDumper(yaml.Dumper):  # pylint: disable=too-many-ancestors
    pass


ProxyDumper.add_representer(NodeMapping, proxy_representer)
ProxyDumper.add_representer(NodeSequence, proxy_representer)
ProxyDumper.add_representer(SliceProxy, proxy_representer)
