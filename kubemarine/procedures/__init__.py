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
from typing import List, OrderedDict, Any, Protocol, runtime_checkable

NO_TASKS_PROCEDURES = ["do", "migrate_kubemarine", "config"]


@runtime_checkable
class Procedure(Protocol):
    def create_context(self, cli_arguments: List[str] = None) -> dict: ...

    def main(self, cli_arguments: List[str] = None) -> Any: ...


@runtime_checkable
class TasksProcedure(Procedure, Protocol):
    @property
    def tasks(self) -> OrderedDict[str, Any]: ...


def import_procedure(name: str) -> Procedure:
    if name in NO_TASKS_PROCEDURES:
        return _import_no_tasks_procedure(name)

    return _import_tasks_procedure(name)


def _import_tasks_procedure(name: str) -> TasksProcedure:
    procedure: TasksProcedure
    if name == "add_node":
        from kubemarine.procedures import add_node as procedure
    elif name == "backup":
        from kubemarine.procedures import backup as procedure
    elif name == "cert_renew":
        from kubemarine.procedures import cert_renew as procedure
    elif name == "check_iaas":
        from kubemarine.procedures import check_iaas as procedure
    elif name == "check_paas":
        from kubemarine.procedures import check_paas as procedure
    elif name == "install":
        from kubemarine.procedures import install as procedure
    elif name == "manage_pss":
        from kubemarine.procedures import manage_pss as procedure
    elif name == "reboot":
        from kubemarine.procedures import reboot as procedure
    elif name == "reconfigure":
        from kubemarine.procedures import reconfigure as procedure
    elif name == "remove_node":
        from kubemarine.procedures import remove_node as procedure
    elif name == "restore":
        from kubemarine.procedures import restore as procedure
    elif name == "upgrade":
        from kubemarine.procedures import upgrade as procedure
    else:
        raise NotImplementedError(f"Procedure {name!r} is not implemented yet")

    return procedure


def _import_no_tasks_procedure(name: str) -> Procedure:
    procedure: Procedure
    if name == "do":
        from kubemarine.procedures import do as procedure
    elif name == "migrate_kubemarine":
        from kubemarine.procedures import migrate_kubemarine as procedure
    elif name == "config":
        from kubemarine.procedures import config as procedure
    else:
        raise NotImplementedError(f"Procedure {name!r} is not implemented yet")

    return procedure


def deimport_procedure(name: str) -> None:
    del sys.modules['kubemarine.procedures.%s' % name]
