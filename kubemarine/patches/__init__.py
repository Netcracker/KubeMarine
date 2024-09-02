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

"""
All files and directories inside kubemarine/patches directory should participate only in patching mechanism,
and relate to the current Kubemarine version.

The whole directory is automatically cleared and reset after new version of Kubemarine is released.
"""

from typing import List

from kubemarine.core.patch import Patch
from kubemarine.patches.p1_pin_kubernetes_version import PinKubernetesVersion

patches: List[Patch] = [
    PinKubernetesVersion(),
]
"""
List of patches that is sorted according to the Patch.priority() before execution.
Patches that have the same priority, are executed in the declared order.
"""
