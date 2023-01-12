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

from tabulate import tabulate

from kubemarine.core.cluster import KubernetesCluster


def schedule_summary_report(cluster: KubernetesCluster, property: str, value: str):
    cluster.context.setdefault('summary_report', []).append([property, value])
    cluster.schedule_cumulative_point(print_summary)


def print_summary(cluster: KubernetesCluster):
    table = tabulate(cluster.context.get('summary_report'),
                     headers=["Property", "Value"],
                     tablefmt="pretty",
                     colalign=("left", "left"))
    cluster.log.info(table)
