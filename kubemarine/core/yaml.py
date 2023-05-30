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

from typing import Union, IO

import ruamel.yaml.resolver
import yaml

from kubemarine.core import os

# Take pattern to resolve float used by ruamel instead of that is used by pyyaml.
# https://sourceforge.net/p/ruamel-yaml/code/ci/0.17.21/tree/resolver.py#l43
# Initially introduced for keepalived that generates random password string.
# The generated string might be also a valid exponential float, and should be dumped with quotes.
# See also:
# https://stackoverflow.com/questions/30458977/yaml-loads-5e-6-as-string-and-not-a-number
# https://github.com/yaml/pyyaml/issues/173
for ir in ruamel.yaml.resolver.implicit_resolvers:
    # YAML 1.1 and float implicit resolver
    if (1, 1) in ir[0] and 'tag:yaml.org,2002:float' in ir[1]:
        float_patched_resolver = (ir[1], ir[2], ir[3])
        # Globally change behaviour of yaml.safe_load and yaml.dump
        yaml.Dumper.add_implicit_resolver(*float_patched_resolver)
        yaml.SafeLoader.add_implicit_resolver(*float_patched_resolver)
        break


def to_yaml(dumper: Union[yaml.Dumper, ruamel.yaml.SafeRepresenter], data: os.MaskedVar):
    return dumper.represent_scalar('tag:yaml.org,2002:str', str(data))


yaml.Dumper.add_representer(os.MaskedVar, to_yaml)


def safe_load(stream: Union[str, IO]):
    return yaml.safe_load(stream)


def safe_dump(data: object) -> str:
    return yaml.safe_dump(data)


def dump(data: object, stream=None) -> str:
    return yaml.dump(data, stream=stream)


def structure_preserver() -> ruamel.yaml.YAML:
    """YAML loader and dumper which saves original structure"""
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.representer.add_representer(os.MaskedVar, to_yaml)
    ruamel_yaml.preserve_quotes = True
    return ruamel_yaml
