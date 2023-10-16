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
import sys
import types


def import_procedure(name: str) -> types.ModuleType:
    module_name = 'kubemarine.procedures.%s' % name
    return __import__(module_name, fromlist=['object'])


def deimport_procedure(name: str) -> None:
    del sys.modules['kubemarine.procedures.%s' % name]
