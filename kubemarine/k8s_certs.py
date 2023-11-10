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
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup


def k8s_certs_overview(control_planes: NodeGroup) -> None:
    for control_plane in control_planes.get_ordered_members_list():
        control_planes.cluster.log.debug(f"Checking certs expiration for control_plane {control_plane.get_node_name()}")
        control_plane.sudo("kubeadm certs check-expiration", hide=False)


def renew_verify(inventory: dict, cluster: KubernetesCluster) -> dict:
    if cluster.context.get('initial_procedure') != 'cert_renew' or "kubernetes" not in cluster.procedure_inventory:
        return inventory

    cert_list = cluster.procedure_inventory["kubernetes"].get("cert-list")
    verify_all_is_absent_or_single(cert_list)

    return inventory


def renew_apply(control_planes: NodeGroup) -> None:
    log = control_planes.cluster.log

    procedure = control_planes.cluster.procedure_inventory["kubernetes"]
    cert_list = procedure["cert-list"]

    for cert in cert_list:
        control_planes.sudo(f"kubeadm certs renew {cert}")

    if "all" in cert_list or "admin.conf" in cert_list:
        # need to update cluster-admin config
        kubernetes.copy_admin_config(log, control_planes)

    # for some reason simple pod delete do not work for certs update - we need to delete containers themselves
    control_planes.call(force_restart_control_plane)

    for control_plane in control_planes.get_ordered_members_list():
        kubernetes.wait_for_any_pods(control_planes.cluster, control_plane, apply_filter=control_plane.get_node_name())


def force_restart_control_plane(control_planes: NodeGroup) -> None:
    cri_impl = control_planes.cluster.inventory['services']['cri']['containerRuntime']
    restart_containers = ["etcd", "kube-scheduler", "kube-apiserver", "kube-controller-manager"]
    c_filter = "grep -e %s" % " -e ".join(restart_containers)

    if cri_impl == "docker":
        control_planes.sudo("sudo docker container rm -f $(sudo docker ps -a | %s | awk '{ print $1 }')" % c_filter, warn=True)
    else:
        control_planes.sudo("sudo crictl rm -f $(sudo crictl ps -a | %s | awk '{ print $1 }')" % c_filter, warn=True)


def verify_all_is_absent_or_single(cert_list: List[str]) -> None:
    if "all" in cert_list and len(cert_list) > 1:
        raise Exception(f"Found 'all' in certs list, but it is not single: {cert_list}")
