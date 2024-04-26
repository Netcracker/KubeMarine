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
import base64
import json
from typing import Callable, Dict, Any, List, Union, Set, Type
from urllib.parse import quote_plus

import yaml
import jinja2

from kubemarine.core import log, utils, errors
from kubemarine.core.proxytypes import (
    Index, Primitive, NodeMapping, ProxyDumper, ProxyJSONEncoder, MutableNode, Node
)

Path = tuple
FILTER = Callable[[str], Any]


class JinjaNode(MutableNode):
    """
    A Node that compiles template strings in the underlying `dict` or `list` on-the-fly during access to its items.
    """

    def __init__(self, delegate: Union[dict, list],
                 *, path: Path, env: 'Environment'):
        super().__init__(delegate)
        self.path = path
        self.env = env

    def _child(self, index: Index, val: Union[list, dict]) -> Node:
        return self._child_type(index)(val, path=self.path + (index,), env=self.env)

    def _child_type(self, _: Index) -> Type['JinjaNode']:
        return JinjaNode

    def _convert(self, index: Index, val: Primitive) -> Primitive:
        if isinstance(val, str) and is_template(val):
            val = self.env.compile_string(val, self.path + (index,))

        return val


class Context(jinja2.runtime.Context):
    """
    An entry point from the jinja templates to the recursively compiled sections of inventory.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.environment: Environment = self.environment

    def resolve_or_missing(self, key: str) -> Any:
        # pylint: disable=protected-access

        v = super().resolve_or_missing(key)

        if v is jinja2.runtime.missing and key in self.environment._recursive_values:
            return self.environment._proxy_values[key]

        return v


class Environment(jinja2.Environment):
    """
    Jinja environment that supports recursive compilation.
    """

    context_class = Context

    def __init__(self, logger: log.EnhancedLogger, recursive_values: dict, *, recursive_extra: Dict[str, Any] = None):
        """
        Instantiate new environment and set default filters.

        :param logger: EnhancedLogger
        :param recursive_values: If templates access to these values, they are automatically compiled if necessary.
        :param recursive_extra: If recursive compilation occurs, these render values are supplied to the template.
        """
        super().__init__()
        self.logger = logger

        self._recursive_values = recursive_values
        self._proxy_values = NodeMapping(self.create_root(self._recursive_values))

        self._compiled: Set[Path] = set()
        self._compiling: List[Path] = []

        self._recursive_extra = {}
        if recursive_extra is not None:
            self._recursive_extra = recursive_extra

        self.policies['json.dumps_function'] = jinja_tojson
        self.filters['toyaml'] = jinja_toyaml

        simple_string_filters: Dict[str, FILTER] = {
            'isipv4': lambda ip: utils.isipv(ip, [4]),
            'isipv6': lambda ip: utils.isipv(ip, [6]),
            'minorversion': utils.minor_version,
            'majorversion': utils.major_version,
            'versionkey': utils.version_key,
            'b64encode': lambda s: base64.b64encode(s.encode()).decode(),
            'b64decode': lambda s: base64.b64decode(s.encode()).decode(),
            'url_quote': quote_plus
        }

        for name, filter_ in simple_string_filters.items():
            def make_filter(n: str, f: FILTER) -> FILTER:
                return lambda s, *args, **kwargs: f(self._check_filter(n, s, *args, *kwargs))

            self.filters[name] = make_filter(name, filter_)

        self.tests['has_role'] = lambda node, role: role in node['roles']
        self.tests['has_roles'] = lambda node, roles: bool(set(node['roles']) & set(roles))

        # we need these filters because rendered cluster.yaml can contain variables like
        # enable: 'true'
        self.filters['is_true'] = utils.strtobool
        self.filters['is_false'] = lambda v: not utils.strtobool(v)

    def create_root(self, delegate: dict) -> Node:
        """
        Create the root wrapper over the recursively compiled container (inventory).

        :param delegate: the root container
        :return: the root wrapper
        """
        return JinjaNode(delegate, path=Path(), env=self)

    def compile_string(self, struct: str, path: Path) -> str:
        """
        Compiles template string at the specified inventory `path`.
        It is called both while going over the inventory,
        and recursively if variables are accessed from templates.

        :param struct: template string
        :param path: path of sections in the inventory
        :return: compiled string
        """
        if path in self._compiled:
            return struct

        if path in self._compiling:
            idx = self._compiling.index(path)
            raise Exception(
                f"Cyclic dynamic variables in inventory{' -> '.join(map(utils.pretty_path, self._compiling[idx:]))}")

        self.logger.verbose("Rendering \"%s\"" % struct)

        self._compiling.append(path)

        try:
            struct = self.from_string(struct).render(self._recursive_extra)
        except errors.BaseKME:
            raise
        except Exception as e:
            raise ValueError(f"Failed to render {struct!r}\nin section {utils.pretty_path(path)}: {e}") from None

        self._compiling.pop()

        self._compiled.add(path)

        self.logger.verbose("\tRendered as \"%s\"" % struct)
        return struct

    def _check_filter(self, filter_: str, struct: str, *args: Any, **kwargs: Any) -> str:
        if args or kwargs:
            raise ValueError(f"Filter {filter_!r} does not support extra arguments")

        if not isinstance(struct, str):
            raise ValueError(f"Filter {filter_!r} can be applied only on string")

        return struct


def jinja_tojson(obj: Any, **kwargs: Any) -> str:
    return json.dumps(obj, cls=ProxyJSONEncoder, **kwargs)


def jinja_toyaml(data: Any) -> str:
    return yaml.dump(data, Dumper=ProxyDumper)


def is_template(struct: str) -> bool:
    return '{{' in struct or '{%' in struct


def compile_node(struct: Union[list, dict], path: List[Union[str, int]], env: Environment) -> Union[list, dict]:
    if isinstance(struct, list):
        for i, v in enumerate(struct):
            struct[i] = compile_object(v, path, i, env)
    else:
        for k, v in struct.items():
            struct[k] = compile_object(v, path, k, env)

    return struct


def compile_object(struct: Union[Primitive, list, dict],
                   path: List[Index], index: Index, env: Environment) -> Union[Primitive, list, dict]:
    path.append(index)
    if isinstance(struct, (list, dict)):
        struct = compile_node(struct, path, env)
    elif isinstance(struct, str) and is_template(struct):
        struct = env.compile_string(struct, Path(path))

    path.pop()
    return struct
