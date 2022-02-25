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


class ReplicaSet(KubernetesObject):

    def __init__(self, cluster: KubernetesCluster, name=None, namespace=None, obj=None):
        super().__init__(cluster, kind='ReplicaSet', name=name, namespace=namespace, obj=obj)

    def is_actual_and_ready(self) -> bool:
        return self.is_available() and self.is_fully_labeled() and self.is_ready()

    def is_ready(self) -> bool:
        desired_number_scheduled = self._obj.get('spec', {}).get('replicas')
        number_ready = self._obj.get('status', {}).get('readyReplicas')
        return desired_number_scheduled is not None \
            and number_ready is not None \
            and desired_number_scheduled == number_ready

    def is_available(self) -> bool:
        desired_number_scheduled = self._obj.get('spec', {}).get('replicas')
        available_number = self._obj.get('status', {}).get('availableReplicas')
        return desired_number_scheduled is not None \
            and available_number is not None \
            and desired_number_scheduled == available_number

    def is_fully_labeled(self) -> bool:
        desired_number_scheduled = self._obj.get('spec', {}).get('replicas')
        fully_labeled_number = self._obj.get('status', {}).get('fullyLabeledReplicas')
        return desired_number_scheduled is not None \
            and fully_labeled_number is not None \
            and desired_number_scheduled == fully_labeled_number
