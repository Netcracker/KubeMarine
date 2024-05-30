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
from typing import List

from kubemarine import kubernetes
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup


def k8s_certs_overview(control_planes: NodeGroup) -> None:
    for control_plane in control_planes.get_ordered_members_list():
        control_planes.cluster.log.debug(f"Checking certs expiration for control_plane {control_plane.get_node_name()}")
        control_plane.sudo("kubeadm certs check-expiration", hide=False, pty=True)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['cert_renew'])
def renew_verify(cluster: KubernetesCluster) -> None:
    if "kubernetes" not in cluster.procedure_inventory:
        return

    cert_list = cluster.procedure_inventory["kubernetes"].get("cert-list")
    verify_all_is_absent_or_single(cert_list)


def renew_apply(control_planes: NodeGroup) -> None:
    log = control_planes.cluster.log

    procedure = control_planes.cluster.procedure_inventory["kubernetes"]
    cert_list = procedure["cert-list"]

    for cert in cert_list:
        control_planes.sudo(f"kubeadm certs renew {cert}", pty=True)

    if "all" in cert_list or "admin.conf" in cert_list:
        # need to update cluster-admin config
        kubernetes.copy_admin_config(log, control_planes)

    # for some reason simple pod delete do not work for certs update - we need to delete containers themselves
    control_planes.call(kubernetes.components.restart_components,
                        components=kubernetes.components.CONTROL_PLANE_COMPONENTS)


def verify_all_is_absent_or_single(cert_list: List[str]) -> None:
    if "all" in cert_list and len(cert_list) > 1:
        raise Exception(f"Found 'all' in certs list, but it is not single: {cert_list}")
