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
from kubemarine import thirdparties
from ..shell import curl, TEMP_FILE, SYNC_CACHE

# pylint: disable=bad-builtin

def resolve_local_path(destination: str, version: str) -> str:
    filename = f"{destination.split('/')[-1]}-{version}"
    target_file = os.path.join(SYNC_CACHE, filename)
    if os.path.exists(target_file):
        return target_file

    source = thirdparties.get_default_thirdparty_source(destination, version, in_public=True)

    print(f"Downloading thirdparty {destination} of version {version} from {source}")
    curl(source, TEMP_FILE)
    os.rename(TEMP_FILE, target_file)

    return target_file