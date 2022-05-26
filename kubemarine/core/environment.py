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

import os
from abc import ABC, abstractmethod

from kubemarine.core import static


class Environment(ABC):
    @property
    @abstractmethod
    def inventory(self) -> dict:
        pass

    @property
    def globals(self) -> dict:
        return static.GLOBALS

    @staticmethod
    def is_deploying_from_windows():
        return os.name == 'nt'
