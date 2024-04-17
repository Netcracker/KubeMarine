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
from typing import Callable, Dict, Any
from urllib.parse import quote_plus

import yaml
import jinja2

from kubemarine.core import log, utils

FILTER = Callable[[str], Any]


def new(_: log.EnhancedLogger, *,
        recursive_compiler: Callable[[str], str] = None,
        precompile_filters: Dict[str, FILTER] = None) -> jinja2.Environment:
    def _precompile(filter_: str, struct: str, *args: Any, **kwargs: Any) -> str:
        if args or kwargs:
            raise ValueError(f"Filter {filter_!r} does not support extra arguments")

        if not isinstance(struct, str):
            raise ValueError(f"Filter {filter_!r} can be applied only on string")

        # maybe we have non compiled string like templates/plugins/calico-{{ globals.compatibility_map }} ?
        return recursive_compiler(struct) if recursive_compiler is not None and is_template(struct) else struct

    env = jinja2.Environment()

    if precompile_filters is None:
        precompile_filters = {}
    precompile_filters['isipv4'] = lambda ip: utils.isipv(ip, [4])
    precompile_filters['minorversion'] = utils.minor_version
    precompile_filters['majorversion'] = utils.major_version
    precompile_filters['versionkey'] = utils.version_key
    precompile_filters['b64encode'] = lambda s: base64.b64encode(s.encode()).decode()
    precompile_filters['b64decode'] = lambda s: base64.b64decode(s.encode()).decode()
    precompile_filters['url_quote'] = quote_plus

    for name, filter_ in precompile_filters.items():
        def make_filter(n: str, f: FILTER) -> FILTER:
            return lambda s, *args, **kwargs: f(_precompile(n, s, *args, *kwargs))

        env.filters[name] = make_filter(name, filter_)

    env.filters['toyaml'] = lambda data: yaml.dump(data, default_flow_style=False)
    env.tests['has_role'] = lambda node, role: role in node['roles']
    env.tests['has_roles'] = lambda node, roles: bool(set(node['roles']) & set(roles))

    # we need these filters because rendered cluster.yaml can contain variables like 
    # enable: 'true'
    env.filters['is_true'] = lambda v: v if isinstance(v, bool) else utils.strtobool(_precompile('is_true', v))
    env.filters['is_false'] = lambda v: not v if isinstance(v, bool) else not utils.strtobool(_precompile('is_false', v))
    return env


def is_template(struct: str) -> bool:
    return '{{' in struct or '{%' in struct
