#!/usr/bin/env python3
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


from collections import OrderedDict

import io
import uuid
from typing import List

from kubemarine import kubernetes, etcd, thirdparties, cri
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine.cri import docker
from kubemarine.procedures import install
from kubemarine import packages


def migrate_cri(cluster: KubernetesCluster) -> None:
    _migrate_cri(cluster, cluster.nodes["worker"].exclude_group(cluster.nodes["control-plane"])
                 .get_ordered_members_list())
    _migrate_cri(cluster, cluster.nodes["control-plane"].get_ordered_members_list())


def _migrate_cri(cluster: KubernetesCluster, node_group: List[NodeGroup]) -> None:
    """
    Migrate CRI from docker to already installed containerd.
    This method works node-by-node, configuring kubelet to use containerd.
    :param cluster: main object describing a cluster
    :param node_group: group of nodes to migrate
    """

    for node in node_group:
        node_config = node.get_config()
        node_name = node.get_node_name()
        is_control_plane = "control-plane" in node_config["roles"]
        if is_control_plane:
            control_plane = node
        else:
            control_plane = cluster.nodes["control-plane"].get_first_member()

        cluster.log.debug(f'Updating thirdparties for node "{node_name}"...')
        thirdparties.install_all_thirparties(node)

        version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
        cluster.log.debug("Migrating \"%s\"..." % node_name)
        drain_cmd = kubernetes.prepare_drain_command(cluster, node_name, disable_eviction=True)
        control_plane.sudo(drain_cmd, hide=False)

        kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
        kubeadm_flags = node.sudo(f"cat {kubeadm_flags_file}").get_simple_out()

        #Removing the --network-plugin=cni switch after the cri migration procedure that was used to run Docker on the cluster.
        #Support for this key has been removed in kubernetes 1.24.
        if kubeadm_flags.find('--network-plugin=cni') != -1:
            kubeadm_flags = kubeadm_flags.replace('--network-plugin=cni', '')

        kubeadm_flags = edit_config(kubeadm_flags)

        node.put(io.StringIO(kubeadm_flags), kubeadm_flags_file, backup=True, sudo=True)

        node.sudo("systemctl stop kubelet")
        docker.prune(node)

        docker_associations = cluster.get_associations_for_node(node.get_host(), 'docker')
        node.sudo(f"systemctl disable {docker_associations['service_name']} --now; "
                  "sudo sh -c 'rm -rf /var/lib/docker/*'")

        cluster.log.debug('Reinstalling CRI...')
        cri.install(node)
        cri.configure(node)

        cluster.log.debug(f'CRI configured! Restoring pods on node "{node_name}"')

        # if there is a disk for docker in "/etc/fstab", then use this disk for containerd
        docker_disk_result = node.sudo("cat /etc/fstab | grep ' /var/lib/docker '", warn=True)
        docker_disk = list(docker_disk_result.values())[0].stdout.strip()
        if docker_disk:
            node.sudo(
                "umount /var/lib/docker && "
                "sudo sed -i 's/ \/var\/lib\/docker / \/var\/lib\/containerd /' /etc/fstab && "
                "sudo sh -c 'rm -rf /var/lib/containerd/*' && "
                "sudo mount -a && "
                "sudo systemctl restart containerd")

        # flushing iptables to delete old cri's rules,
        # existence of those rules could lead to services unreachable
        node.sudo(
            "sudo iptables -t nat -F && "
            "sudo iptables -t raw -F && "
            "sudo iptables -t filter -F && "
            # hotfix for Ubuntu 22.04
            "sudo systemctl stop kubepods-burstable.slice || true && "
            "sudo systemctl restart containerd && "
            # start kubelet
            "sudo systemctl restart kubelet")

        if is_control_plane:
            kubernetes.wait_uncordon(node)
        else:
            control_plane.sudo(f"kubectl uncordon {node_name}", hide=False)

        if is_control_plane:
            kubernetes.wait_for_any_pods(cluster, node, apply_filter=node_name)
            # check ETCD health
            etcd.wait_for_health(cluster, node)

        packages_list = []
        for package_name in docker_associations['package_name']:
            if not package_name.startswith('containerd'):
                packages_list.append(package_name)
        cluster.log.warning("The following packages will be removed: %s" % packages_list)
        if packages_list:
            packages.remove(node, include=packages_list, warn=True, hide=False)

        # change annotation for cri-socket
        control_plane.sudo(f"sudo kubectl annotate node {node_name} "
                           f"--overwrite kubeadm.alpha.kubernetes.io/cri-socket=/run/containerd/containerd.sock")

        # delete docker socket
        node.sudo("rm -rf /var/run/docker.sock", hide=False)


def release_calico_leaked_ips(cluster: KubernetesCluster) -> None:
    """
    During drain command we ignore daemon sets, as result this such pods as ingress-nginx-controller arent't deleted before migration.
    For this reason their ips can stay in calico ipam despite they aren't used. You can check this, if you run "calicoctl ipam check --show-problem-ips" right after apply_new_cri task.
    Those ips are cleaned by calico garbage collector, but it can take about 20 minutes.
    This task releases problem ips with force.
    """
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    cluster.log.debug("Getting leaked ips...")
    random_report_name = "/tmp/%s.json" % uuid.uuid4().hex
    result = first_control_plane.sudo(f"calicoctl ipam check --show-problem-ips -o {random_report_name} | grep 'leaked' || true", hide=False)
    leaked_ips = result.get_simple_out()
    leaked_ips_count = leaked_ips.count('leaked')
    cluster.log.debug(f"Found {leaked_ips_count} leaked ips")
    if leaked_ips_count != 0:
        first_control_plane.sudo(f"calicoctl ipam release --from-report={random_report_name} --force", hide=False)
        cluster.log.debug("Leaked ips was released")
    first_control_plane.sudo(f"rm {random_report_name}", hide=False)


def edit_config(kubeadm_flags: str) -> str:
    kubeadm_flags = kubernetes.config_changer(kubeadm_flags, "--container-runtime=remote")
    return kubernetes.config_changer(kubeadm_flags,
                                     "--container-runtime-endpoint=unix:///run/containerd/containerd.sock")


tasks = OrderedDict({
    "add_repos": install.system_prepare_package_manager_configure,
    "apply_new_cri": migrate_cri,
    "release_calico_ipam_leacked_ips": release_calico_leaked_ips
})


class MigrateCRIAction(Action):
    def __init__(self) -> None:
        super().__init__('migrate cri', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
        Script for automated migration from docker to containerd.

        How to use:

        '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure="migrate_cri")
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([MigrateCRIAction()]).run_flow(context)


if __name__ == '__main__':
    main()
