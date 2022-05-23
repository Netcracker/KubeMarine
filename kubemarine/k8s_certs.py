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

from kubemarine import kubernetes

supported_k8s_certs = ["all",
                       "apiserver", "apiserver-etcd-client", "apiserver-kubelet-client",
                       "etcd-healthcheck-client", "etcd-peer", "etcd-server",
                       "admin.conf", "controller-manager.conf", "scheduler.conf",
                       "front-proxy-client"]
version_kubectl_alpha_removed = "v1.21.0"


def k8s_certs_overview(control_planes):
    if kubernetes.version_higher_or_equal(control_planes.cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                          version_kubectl_alpha_removed):
        for control_plane in control_planes.get_ordered_members_list(provide_node_configs=True):
            control_planes.cluster.log.debug(f"Checking certs expiration for control_plane {control_plane['name']}")
            control_plane['connection'].sudo("kubeadm certs check-expiration", hide=False)
    else:
        for control_plane in control_planes.get_ordered_members_list(provide_node_configs=True):
            control_planes.cluster.log.debug(f"Checking certs expiration for control_plane {control_plane['name']}")
            control_plane['connection'].sudo("kubeadm alpha certs check-expiration", hide=False)


def renew_verify(inventory, cluster):
    if cluster.context.get('initial_procedure') != 'cert_renew' or "kubernetes" not in cluster.procedure_inventory:
        return inventory

    cert_list = cluster.procedure_inventory["kubernetes"].get("cert-list")
    verify_cert_list_format(cert_list)
    verify_certs_supported(cert_list)
    verify_all_is_absent_or_single(cert_list)

    return inventory


def renew_apply(control_planes):
    log = control_planes.cluster.log

    procedure = control_planes.cluster.procedure_inventory["kubernetes"]
    cert_list = remove_certs_duplicates(procedure["cert-list"])

    if kubernetes.version_higher_or_equal(control_planes.cluster.inventory['services']['kubeadm']['kubernetesVersion'],
                                          version_kubectl_alpha_removed):
        for cert in cert_list:
            control_planes.sudo(f"kubeadm certs renew {cert}")
    else:
        for cert in cert_list:
            control_planes.sudo(f"kubeadm alpha certs renew {cert}")

    if "all" in cert_list or "admin.conf" in cert_list:
        # need to update cluster-admin config
        kubernetes.copy_admin_config(log, control_planes)

    control_planes.call(force_renew_kubelet_serving_certs)

    # for some reason simple pod delete do not work for certs update - we need to delete containers themselves
    control_planes.call(force_restart_control_plane)

    for control_plane in control_planes.get_ordered_members_list(provide_node_configs=True):
        kubernetes.wait_for_any_pods(control_planes.cluster, control_plane["connection"], apply_filter=control_plane["name"])


def force_restart_control_plane(control_planes):
    cri_impl = control_planes.cluster.inventory['services']['cri']['containerRuntime']
    restart_containers = ["etcd", "kube-scheduler", "kube-apiserver", "kube-controller-manager"]
    c_filter = "grep -e %s" % " -e ".join(restart_containers)

    if cri_impl == "docker":
        control_planes.sudo("sudo docker container rm -f $(sudo docker ps -a | %s | awk '{ print $1 }')" % c_filter, warn=True)
    else:
        control_planes.sudo("sudo crictl rm -f $(sudo crictl ps -a | %s | awk '{ print $1 }')" % c_filter, warn=True)


def force_renew_kubelet_serving_certs(control_planes):
    # Delete *serving* kubelet cert (kubelet.crt) and restart kubelet to create new up-to-date cert.
    # Client kubelet cert (kubelet.conf) is assumed to be updated automatically by kubelet.
    for control_plane in control_planes.get_ordered_members_list():
        control_plane.sudo(f"rm -f /var/lib/kubelet/pki/kubelet.crt /var/lib/kubelet/pki/kubelet.key")
    control_planes.sudo("systemctl restart kubelet")


def verify_cert_list_format(cert_list):
    if cert_list is None or not isinstance(cert_list, list) or len(cert_list) == 0:
        raise Exception("Incorrect k8s certs renew configuration, 'cert_list' list should be present and non-empty")
    return True


def verify_certs_supported(cert_list):
    for line in cert_list:
        if line not in supported_k8s_certs:
            raise Exception(f"Found unsupported cert: {line}, list of supported certs: {supported_k8s_certs}")
    return True


def verify_all_is_absent_or_single(cert_list):
    if "all" in cert_list and len(cert_list) > 1:
        raise Exception(f"Found 'all' in certs list, but it is not single: {cert_list}")
    return True


def remove_certs_duplicates(cert_list):
    return set(cert_list)
