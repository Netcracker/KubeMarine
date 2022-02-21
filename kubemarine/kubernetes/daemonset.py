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


class DaemonSet(KubernetesObject):

    def __init__(self, cluster: KubernetesCluster, name=None, namespace=None, obj=None):
        super().__init__(cluster, kind='DaemonSet', name=name, namespace=namespace, obj=obj)

    def is_actual_and_ready(self) -> bool:
        return self.is_ready() and self.is_up_to_date()

    def is_up_to_date(self) -> bool:
        desired_number_scheduled = self._obj.get('status', {}).get('desiredNumberScheduled')
        updated_number_scheduled = self._obj.get('status', {}).get('updatedNumberScheduled')
        return desired_number_scheduled is not None \
            and updated_number_scheduled is not None \
            and desired_number_scheduled == updated_number_scheduled

    def is_ready(self) -> bool:
        desired_number_scheduled = self._obj.get('status', {}).get('desiredNumberScheduled')
        number_ready = self._obj.get('status', {}).get('numberReady')
        return desired_number_scheduled is not None \
            and number_ready is not None \
            and desired_number_scheduled == number_ready

    def is_scheduled(self) -> bool:
        desired_number_scheduled = self._obj.get('status', {}).get('desiredNumberScheduled')
        current_number_scheduled = self._obj.get('status', {}).get('currentNumberScheduled')
        return desired_number_scheduled is not None \
            and current_number_scheduled is not None \
            and desired_number_scheduled == current_number_scheduled
