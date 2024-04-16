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
from typing import Tuple, Optional

from deepmerge import Merger  # type: ignore[import-untyped]


def is_list_extends(nxt: list, path: list) -> bool:
    return get_strategy_position(nxt, path)[0] == 'merge'


def get_strategy_position(nxt: list, path: list) -> Tuple[Optional[str], int]:
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

    return strategy, strategy_definition_position


def list_merger(_: Merger, path: list, base: list, nxt: list) -> list:
    strategy, strategy_definition_position = get_strategy_position(nxt, path)

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


default_merger: Merger = Merger(
    [
        (list, [list_merger]),
        (dict, ["merge"])
    ],
    ["override"],
    ["override"]
)

override_merger: Merger = Merger(
    [
        (list, ["override"]),
        (dict, ["merge"])
    ],
    ["override"],
    ["override"]
)
