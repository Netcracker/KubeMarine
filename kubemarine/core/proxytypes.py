# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from abc import ABC, abstractmethod
from typing import Any, Union, Sequence, List, Iterator, Mapping, Type, Dict

import yaml

Index = Union[str, int]
Primitive = Union[str, int, bool, float]


class Proxy(ABC):
    """
    Abstract class that proxies getter methods to some other container.
    """

    def __repr__(self) -> str:
        return repr(self._KM_materialize())

    @abstractmethod
    def _KM_materialize(self) -> Any:
        """
        Create real container that can be serialized.
        This method triggers access to all the items in the proxied container.

        :return: real container that can be serialized.
        """
        pass


class DelegatingProxy(Proxy, ABC):
    """
    Abstract class that proxies getter methods to some real container.
    """

    @abstractmethod
    def _KM_unsafe(self) -> Union[dict, list]:
        """
        Real proxied `dict` or `list`. It can be not the same as the proxied container.
        Should be used only to obtain sequence of indexes (`str` keys of `dict`, or `int` indexes of `list`).

        :return: read proxied `dict` or `list`.
        """
        pass

    @abstractmethod
    def _KM__getitem__(self, index: Index) -> Union[Primitive, Proxy]:
        """
        Get item from `dict` by string key, or from `list` by integer index.
        If the item is also a container, it should be proxied.

        :param index: key of either `str`, or `int` type.
        :return: primitive value or Proxy
        """
        pass


class MappingProxy(DelegatingProxy, Mapping[str, Any], ABC):
    """
    The main facade that proxies all mapping methods to some real mapping.
    """

    def __getitem__(self, k: str) -> Any:
        return self._KM__getitem__(k)

    def __len__(self) -> int:
        return len(self._KM_unsafe())

    def __iter__(self) -> Iterator[str]:
        return iter(self._KM_unsafe())

    def _KM_materialize(self) -> Any:
        return dict(self)


class SequenceProxy(DelegatingProxy, Sequence[Any], ABC):
    """
    The main facade that proxies all sequence methods to some real sequence.
    """

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
    """
    Implementation of `slice` over SequenceProxy.
    """

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
    """
    Highly extendable wrapper over `dict` or `list`.
    """

    def __init__(self, delegate: Union[dict, list]):
        self.delegate = delegate

    def descend(self, index: Index) -> Union[Primitive, 'Node']:
        """
        The main custom implementation to access the items of real `dict` or `list` from Proxies.

        Get a child item / value by the specified `index` from the underlying container.

        If the child item is also a `dict` or `list`, wrap it with the new instance of `Node`
        with (probably) its own logic to resolve items.

        If the child item is a primitive value, it can be arbitrarily converted.

        :param index: key of either `str`, or `int` type.
        :return: primitive value or new child Node instance.
        """
        val: Union[Primitive, list, dict] = self.delegate[index]  # type: ignore[index]
        if isinstance(val, (list, dict)):
            return self._child(index, val)

        return val

    def _child(self, index: Index, val: Union[list, dict]) -> 'Node':
        """
        Instantiate new Node wrapper over the specified child item `val`.
        It can be overridden if derived class has additional constructor parameters,
        but should always instantiate an instance of `_child_type`.

        :param index: key of either `str`, or `int` type.
        :param val: wrapped `dict` or `list`.
        :return: new child Node.
        """
        return self._child_type(index)(val)

    def _child_type(self, _: Index) -> Type['Node']:
        """
        Return `Node` class that should wrap a child item by the specified `index`.

        To preserve behaviour of parent `Node`, the method should be overridden to return the derived `Node` class.

        :return: `Node` class to wrap child item.
        """
        return Node


class MutableNode(Node, ABC):
    """
    A Node that can change underlying `dict` or `list` on-the-fly during access to its items.
    """

    def descend(self, index: Index) -> Union[Primitive, Node]:
        child = super().descend(index)
        if isinstance(child, Node):
            return child

        val = self._convert(index, child)
        self.delegate[index] = val  # type: ignore[index]

        return val

    @abstractmethod
    def _convert(self, index: Index, val: Primitive) -> Primitive:
        """
        Convert primitive value before putting to the underlying container.

        :param index: key of either `str`, or `int` type.
        :param val: primitive value
        :return: converted value
        """
        pass

    def _child_type(self, _: Index) -> Type[Node]:
        return MutableNode


class NodeProxy(DelegatingProxy, ABC):
    """
    Abstract class that proxies getter methods to an instance of `Node`.
    """

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
    """
    Mapping that proxies all getter methods to an instance of `Node`.
    """
    pass


class NodeSequence(NodeProxy, SequenceProxy):
    """
    Sequence that proxies all getter methods to an instance of `Node`.
    """
    pass


class ProxyJSONEncoder(json.JSONEncoder):
    """
    Supports serialization of any Proxy to JSON.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, Proxy):
            return o._KM_materialize()  # pylint: disable=protected-access

        return super().default(o)


def proxy_representer(dumper: yaml.Dumper, data: Proxy) -> Any:
    val = data._KM_materialize()  # pylint: disable=protected-access
    return dumper.yaml_representers[type(val)](dumper, val)


class ProxyDumper(yaml.Dumper):  # pylint: disable=too-many-ancestors
    """
    Supports serialization of any `Node` proxy to YAML.
    """
    pass


ProxyDumper.add_representer(NodeMapping, proxy_representer)
ProxyDumper.add_representer(NodeSequence, proxy_representer)
ProxyDumper.add_representer(SliceProxy, proxy_representer)
