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

from __future__ import annotations

import io
import json
import uuid
from copy import deepcopy
from typing import TypeVar, Optional

import yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RunnersResult
from kubemarine.core.group import NodeGroup

_T = TypeVar('_T', bound='KubernetesObject')


class KubernetesObject:
    def __init__(self, cluster: KubernetesCluster, kind: str = None, name: str = None,
                 namespace: str = None, obj: dict = None) -> None:

        self._cluster = cluster
        self._reload_result: Optional[RunnersResult] = None

        if not kind and not name and not namespace and not obj:
            raise RuntimeError('Not enough parameter values to construct the object')
        if obj:
            self._obj = obj
        else:
            if not kind or not name or not namespace:
                raise RuntimeError('An unsynchronized object has not enough parameters '
                                   'to be reloaded')
            self._obj = {
                "kind": kind,
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                }
            }

    def __str__(self) -> str:
        if self._reload_result is not None and self._reload_result.failed:
            return self._reload_result.stderr
        return self.to_yaml()

    @property
    def obj(self) -> dict:
        return deepcopy(self._obj)

    @property
    def uid(self) -> str:
        uid: Optional[str] = self._obj['metadata'].get('uid')
        if uid:
            return uid

        return str(uuid.uuid4())

    @property
    def kind(self) -> str:
        kind: str = self._obj['kind'].lower()
        return kind

    @property
    def namespace(self) -> str:
        namespace: str = self._obj['metadata']['namespace'].lower()
        return namespace

    @property
    def name(self) -> str:
        name: str = self._obj['metadata']['name'].lower()
        return name

    def to_json(self) -> str:
        return json.dumps(self._obj)

    def to_yaml(self) -> str:
        data: str = yaml.dump(self._obj)
        return data

    def is_reloaded(self) -> bool:
        return bool(self._reload_result)

    def reload(self: _T, control_plane: NodeGroup = None, suppress_exceptions: bool = False) -> _T:
        if not control_plane:
            control_plane = self._cluster.nodes['control-plane'].get_any_member()
        cmd = f'kubectl get {self.kind} -n {self.namespace} {self.name} -o json'
        result = control_plane.sudo(cmd, warn=suppress_exceptions)
        self._cluster.log.verbose(result)
        self._reload_result = result.get_simple_result()
        if self._reload_result:
            self._obj = json.loads(self._reload_result.stdout)
        return self

    def apply(self, control_plane: NodeGroup = None) -> None:
        if not control_plane:
            control_plane = self._cluster.nodes['control-plane'].get_any_member()

        json_str = self.to_json()
        obj_filename = "_".join([self.kind, self.namespace, self.name, self.uid]) + '.json'
        obj_path = f'/tmp/{obj_filename}'

        control_plane.put(io.StringIO(json_str), obj_path, sudo=True)
        control_plane.sudo(f'kubectl apply -f {obj_path} && sudo rm -f {obj_path}')
