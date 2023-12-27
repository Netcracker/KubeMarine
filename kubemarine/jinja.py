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


def new(_: log.EnhancedLogger, *,
        recursive_compiler: Callable[[str], str] = None) -> jinja2.Environment:
    def _precompile(filter_: str, struct: str) -> str:
        if not isinstance(struct, str):
            raise ValueError(f"Filter {filter_!r} can be applied only on string")

        # maybe we have non compiled string like templates/plugins/calico-{{ globals.compatibility_map }} ?
        return recursive_compiler(struct) if recursive_compiler is not None and is_template(struct) else struct

    env = jinja2.Environment()

    precompile_filters: Dict[str, Callable[[str], Any]] = {}
    precompile_filters['isipv4'] = lambda ip: utils.isipv(ip, [4])
    precompile_filters['minorversion'] = utils.minor_version
    precompile_filters['majorversion'] = utils.major_version
    precompile_filters['b64encode'] = lambda s: base64.b64encode(s.encode()).decode()
    precompile_filters['b64decode'] = lambda s: base64.b64decode(s.encode()).decode()
    precompile_filters['url_quote'] = lambda u: quote_plus(u)

    for name, filter_ in precompile_filters.items():
        env.filters[name] = lambda s, n=name, f=filter_: f(_precompile(n, s))

    env.filters['toyaml'] = lambda data: yaml.dump(data, default_flow_style=False)
    env.tests['has_role'] = lambda node, role: role in node['roles']

    # we need these filters because rendered cluster.yaml can contain variables like 
    # enable: 'true'
    env.filters['is_true'] = lambda v: v is True or utils.strtobool(_precompile('is_true', v))
    env.filters['is_false'] = lambda v: v is False or not utils.strtobool(_precompile('is_false', v))
    return env


def is_template(struct: str) -> bool:
    return '{{' in struct or '{%' in struct
