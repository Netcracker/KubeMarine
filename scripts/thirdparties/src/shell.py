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

import os
import subprocess
import sys
from typing import List
from urllib import request

# pylint: disable=bad-builtin

SYNC_CACHE = os.path.abspath(f"{__file__}/../../.synccache")
TEMP_FILE = os.path.join(SYNC_CACHE, "tempfile")


def info(message: str) -> None:
    if os.name != 'nt':
        message = f'\033[1;32m{message}\033[0m'
    print(message)


def fatal(message: str) -> None:
    print(f'\033[1;31m{message}\033[0m')
    sys.exit(1)


def run(args: List[str]) -> str:
    print(f" > {' '.join(args)}")
    return subprocess.run(args, capture_output=True, check=True) \
        .stdout.decode('utf-8')


def curl(source: str, filepath: str) -> None:
    if os.path.exists(filepath):
        os.remove(filepath)

    request.urlretrieve(source, filepath)
