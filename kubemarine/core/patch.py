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
import enum
from abc import ABC, abstractmethod
from functools import total_ordering

from kubemarine.core.action import Action


@total_ordering
class _Priority(enum.Enum):
    INVENTORY_ONLY = 0
    "The patch should only change the inventory. Enrichment is prohibited."

    SOFTWARE_UPGRADE = 1
    "This is a service patch that should be instantiated only automatically by migrate_kubemarine.py"

    REGULAR = 2
    """
    The patch can access and make some operations on the cluster.
    Changes in the inventory are possible, but they should not affect the software upgrade procedure.
    """

    def __lt__(self, other: '_Priority') -> bool:
        return self.value < other.value


class Patch(ABC):
    def __init__(self, identifier: str):
        self.identifier = identifier

    @abstractmethod
    def priority(self) -> _Priority:
        pass

    @property
    @abstractmethod
    def action(self) -> Action:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass


class InventoryOnlyPatch(Patch, ABC):
    """
    The patch should only change the inventory.
    Enrichment is prohibited. Calling DynamicResources.cluster() is prohibited.
    Patches if this type are executed first.
    """

    def priority(self) -> _Priority:
        return _Priority.INVENTORY_ONLY


class _SoftwareUpgradePatch(Patch, ABC):
    """This is a service patch that should be extended only by predefined set of classes inside migrate_kubemarine.py"""

    def priority(self) -> _Priority:
        return _Priority.SOFTWARE_UPGRADE


class RegularPatch(Patch, ABC):
    """
    The patch can access and make some operations on the cluster.
    Changes in the inventory are possible, but they should not affect the software upgrade procedure.
    Patches if this type are executed last.
    """

    def priority(self) -> _Priority:
        return _Priority.REGULAR
