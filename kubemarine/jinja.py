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

import yaml
import jinja2

from kubemarine.core import defaults


def new(log, root=None):
    if root is None:
        root = {}
    env = jinja2.Environment()
    env.filters['toyaml'] = lambda data: yaml.dump(data, default_flow_style=False)
    env.filters['isipv4'] = lambda ip: ":" not in precompile(log, ip, root)
    env.filters['minorversion'] = lambda version: ".".join(precompile(log, version, root).split('.')[0:2])
    env.filters['majorversion'] = lambda version: precompile(log, version, root).split('.')[0]
    # we need these filters because rendered cluster.yaml can contain variables like 
    # enable: 'true'
    env.filters['is_true'] = lambda v: v in ['true', 'True', 'TRUE', True]
    env.filters['is_false'] = lambda v: v in ['false', 'False', 'FALSE', False]
    return env


def precompile(log, struct, root):
    # maybe we have non compiled string like templates/plugins/calico-{{ globals.compatibility_map }} ?
    if '{{' in struct or '{%' in struct:
        struct = defaults.compile_object(log, struct, root)
    return struct
