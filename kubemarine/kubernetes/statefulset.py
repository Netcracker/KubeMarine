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

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.kubernetes.object import KubernetesObject


class StatefulSet(KubernetesObject):

    def __init__(self, cluster: KubernetesCluster, name=None, namespace=None, obj=None):
        super().__init__(cluster, kind='StatefulSet', name=name, namespace=namespace, obj=obj)

    def is_actual_and_ready(self) -> bool:
        return self.is_updated() and self.is_ready()

    def is_ready(self) -> bool:
        desired_number = self._obj.get('spec', {}).get('replicas')
        ready_number = self._obj.get('status', {}).get('readyReplicas')
        return desired_number is not None \
            and ready_number is not None \
            and desired_number == ready_number

    def is_updated(self) -> bool:
        desired_number = self._obj.get('spec', {}).get('replicas')
        updated_number = self._obj.get('status', {}).get('updatedReplicas')
        return desired_number is not None \
            and updated_number is not None \
            and desired_number == updated_number

    def is_scheduled(self) -> bool:
        desired_number = self._obj.get('spec', {}).get('replicas')
        current_number = self._obj.get('status', {}).get('currentReplicas')
        return desired_number is not None \
            and current_number is not None \
            and desired_number == current_number
