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

from deepmerge import Merger


def list_merger(config, path, base, nxt):
    strategy = None
    strategy_definition_position = 0
    for i, v in enumerate(nxt):
        if isinstance(v, dict) and '<<' in v:
            if strategy is not None:
                raise Exception(f"Found more than one merge strategy definitions at path {path}.")
            strategy = v.get('<<')
            strategy_definition_position = i
            if v.keys() != {'<<'} or strategy not in ('replace', 'merge'):
                raise Exception(f"Unexpected merge strategy definition {v} at path {path}.")

    if strategy is None:
        return nxt

    elements_after = nxt[(strategy_definition_position + 1):]
    elements_before = nxt[:strategy_definition_position]
    # do not modify source list
    nxt = []
    nxt.extend(elements_before)
    if strategy == 'merge':
        nxt.extend(base)
    nxt.extend(elements_after)

    return nxt


default_merger = Merger(
    [
        (list, [list_merger]),
        (dict, ["merge"])
    ],
    ["override"],
    ["override"]
)