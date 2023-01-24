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

from kubemarine import kubernetes, etcd, thirdparties, cri
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.cri import docker
from kubemarine.procedures import install
from kubemarine.core.yaml_merger import default_merger
from kubemarine import packages


def enrich_inventory(inventory, cluster):
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory

    os_family = cluster.get_os_family()
    if os_family in ('unknown', 'unsupported', 'multiple'):
        raise Exception("Migration of CRI is possible only for cluster "
                        "with all nodes having the same and supported OS family")

    enrichment_functions = [
        _prepare_yum_repos,
        _prepare_packages,
        _configure_containerd_on_nodes,
        _prepare_crictl
    ]
    for enrichment_fn in enrichment_functions:
        cluster.log.verbose('Calling fn "%s"' % enrichment_fn.__qualname__)
        inventory = enrichment_fn(cluster, inventory)
    return inventory


def _prepare_yum_repos(cluster: KubernetesCluster, inventory: dict, finalization=False):
    if not cluster.procedure_inventory.get("yum", {}):
        cluster.log.debug("Skipped - no yum section defined in procedure config file")
        return inventory

    if not cluster.procedure_inventory["yum"].get("repositories", {}):
        cluster.log.debug("No repositories will be added on nodes")
        return inventory

    if not inventory["services"].get("yum", {}):
        inventory["services"]["yum"] = {}

    if inventory["services"]["yum"].get("repositories", {}):
        default_merger.merge(inventory["services"]["yum"]["repositories"],
                             cluster.procedure_inventory["yum"]["repositories"])
    else:
        default_merger.merge(inventory["services"]["yum"],
                             cluster.procedure_inventory["yum"])
    return inventory


def _prepare_packages(cluster: KubernetesCluster, inventory: dict, finalization=False):
    if not cluster.procedure_inventory.get("packages", {}):
        cluster.log.debug("Skipped - no packages defined in procedure config file")
        return inventory

    if not cluster.procedure_inventory["packages"].get("associations", {}):
        cluster.log.debug("Skipped - no associations defined in procedure config file")
        return inventory

    if finalization:
        # Despite we enrich OS specific section inside system.enrich_upgrade_inventory,
        # we still merge global associations section because it has priority during enrichment.
        inventory["services"].setdefault("packages", {}).setdefault("associations", {})
        default_merger.merge(inventory["services"]["packages"]["associations"],
                             cluster.procedure_inventory["packages"]["associations"])
    else:
        # Merge OS family specific section. It is already enriched in packages.enrich_inventory_associations
        # This effectively allows to specify only global section but not for specific OS family.
        # This restriction is because system.enrich_upgrade_inventory goes after packages.enrich_inventory_associations,
        # but in future the restriction can be eliminated.
        default_merger.merge(inventory["services"]["packages"]["associations"][cluster.get_os_family()],
                             cluster.procedure_inventory["packages"]["associations"])

    return inventory


def _prepare_crictl(cluster: KubernetesCluster, inventory: dict, finalization=False):
    if cluster.procedure_inventory.get("thirdparties", {}) \
            and cluster.procedure_inventory["thirdparties"].get("/usr/bin/crictl.tar.gz", {}):

        if not inventory["services"].get("thirdparties", {}):
            inventory["services"]["thirdparties"] = {}

        default_merger.merge(inventory["services"]["thirdparties"],
                             cluster.procedure_inventory["thirdparties"])
        cluster.log.debug("Third-party crictl added")
        return inventory
    else:
        return inventory


def _configure_containerd_on_nodes(cluster: KubernetesCluster, inventory: dict):
    if inventory["services"]["cri"]["containerRuntime"] == cluster.procedure_inventory["cri"]["containerRuntime"]:
        raise Exception("You already have such cri or you should explicitly specify 'cri.containerRuntime: docker' in cluster.yaml")

    inventory = _merge_containerd(cluster, inventory)
    return inventory


def _merge_containerd(cluster, inventory, finalization=False):
    if not inventory["services"].get("cri", {}):
        inventory["services"]["cri"] = {}

    if inventory["services"]["cri"].get("dockerConfig", {}):
        del inventory["services"]["cri"]["dockerConfig"]

    default_merger.merge(inventory["services"]["cri"], cluster.procedure_inventory["cri"])
    return inventory


def migrate_cri(cluster):
    _migrate_cri(cluster, cluster.nodes["worker"].exclude_group(cluster.nodes["control-plane"])
                 .get_ordered_members_list(provide_node_configs=True))
    _migrate_cri(cluster, cluster.nodes["control-plane"].get_ordered_members_list(provide_node_configs=True))


def _migrate_cri(cluster: KubernetesCluster, node_group: dict):
    """
    Migrate CRI from docker to already installed containerd.
    This method works node-by-node, configuring kubelet to use containerd.
    :param cluster: main object describing a cluster
    :param node_group: group of nodes to migrate
    """

    for node in node_group:
        if "control-plane" in node["roles"]:
            control_plane = node
        else:
            control_plane = cluster.nodes["control-plane"].get_first_member(provide_node_configs=True)

        cluster.log.debug(f'Updating thirdparties for node "{node["connect_to"]}..."')
        thirdparties.install_all_thirparties(node["connection"])

        version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
        cluster.log.debug("Migrating \"%s\"..." % node["name"])
        disable_eviction = True
        drain_cmd = kubernetes.prepare_drain_command(node, version, cluster.globals, disable_eviction, cluster.nodes)
        control_plane["connection"].sudo(drain_cmd, is_async=False, hide=False)
        # `kubectl drain` ignores system pods, delete them explicitly
        if "control-plane" in node["roles"]:
            node["connection"].sudo(f"kubectl -n kube-system delete pod etcd-{node['name']} "
                                    f"kube-apiserver-{node['name']} "
                                    f"kube-controller-manager-{node['name']} "
                                    f"kube-scheduler-{node['name']} "
                                    f"$(sudo kubectl describe node {node['name']} | "
                                    "grep -E 'kube-system\\s+kube-proxy-[a-z,0-9]{{5}}' | awk '{{print $2}}')",
                                    is_async=False, hide=False).get_simple_out()

        kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
        kubeadm_flags = node["connection"].sudo(f"cat {kubeadm_flags_file}",
                                                is_async=False).get_simple_out()

        #Removing the --network-plugin=cni switch after the cri migration procedure that was used to run Docker on the cluster.
        #Support for this key has been removed in kubernetes 1.24.
        if kubeadm_flags.find('--network-plugin=cni') != -1:
            kubeadm_flags = kubeadm_flags.replace('--network-plugin=cni', '')

        kubeadm_flags = edit_config(kubeadm_flags)

        node["connection"].put(io.StringIO(kubeadm_flags), kubeadm_flags_file, backup=True, sudo=True)

        node["connection"].sudo("systemctl stop kubelet")
        docker.prune(node["connection"])

        docker_associations = cluster.get_associations_for_node(node['connect_to'], 'docker')
        node["connection"].sudo(f"systemctl disable {docker_associations['service_name']} --now; "
                                 "sudo sh -c 'rm -rf /var/lib/docker/*'")

        cluster.log.debug('Reinstalling CRI...')
        cri.install(node["connection"])
        cri.configure(node["connection"])

        cluster.log.debug(f'CRI configured! Restoring pods on node "{node["connect_to"]}"')

        # if there is a disk for docker in "/etc/fstab", then use this disk for containerd
        docker_disk_result = node["connection"].sudo("cat /etc/fstab | grep ' /var/lib/docker '", warn=True)
        docker_disk = list(docker_disk_result.values())[0].stdout.strip()
        if docker_disk:
            node['connection'].sudo("umount /var/lib/docker && "
                                    "sudo sed -i 's/ \/var\/lib\/docker / \/var\/lib\/containerd /' /etc/fstab && "
                                    "sudo sh -c 'rm -rf /var/lib/containerd/*' && "
                                    "sudo mount -a && "
                                    "sudo systemctl restart containerd")

        # flushing iptables to delete old cri's rules,
        # existence of those rules could lead to services unreachable
        node["connection"].sudo("sudo iptables -t nat -F && "
                                "sudo iptables -t raw -F && "
                                "sudo iptables -t filter -F && "
                                # hotfix for Ubuntu 22.04
                                "sudo systemctl stop kubepods-burstable.slice || true && "
                                "sudo systemctl restart containerd && "
                                # start kubelet
                                "sudo systemctl restart kubelet")
        control_plane["connection"].sudo(f"sudo kubectl uncordon {node['name']}", is_async=False, hide=False)
        if "control-plane" in node["roles"]:
            # hotfix for Ubuntu 22.04 and Kubernetes v1.21.2
            if version == "v1.21.2":
                node['connection'].sudo("sleep 30 && "
                                        "sudo kubectl -n kube-system  delete pod "
                                        "$(sudo kubectl -n kube-system get pod --field-selector='status.phase=Pending' | "
                                        "grep 'kube-proxy' | awk '{ print $1 }') || true")
            kubernetes.wait_for_any_pods(cluster, node["connection"], apply_filter=node["name"])
            # check ETCD health
            etcd.wait_for_health(cluster, node["connection"])

        packages_list = []
        for package_name in docker_associations['package_name']:
            if not package_name.startswith('containerd'):
                packages_list.append(package_name)
        cluster.log.warning("The following packages will be removed: %s" % packages_list)
        if packages_list:
            packages.remove(node["connection"], include=packages_list, warn=True, hide=False)

        # change annotation for cri-socket
        control_plane["connection"].sudo(f"sudo kubectl annotate node {node['name']} "
                                  f"--overwrite kubeadm.alpha.kubernetes.io/cri-socket=/run/containerd/containerd.sock",
                                  is_async=False, hide=True)

        # delete docker socket
        node["connection"].sudo("rm -rf /var/run/docker.sock", hide=False)


def release_calico_leaked_ips(cluster):
    """
    During drain command we ignore daemon sets, as result this such pods as ingress-nginx-controller arent't deleted before migration.
    For this reason their ips can stay in calico ipam despite they aren't used. You can check this, if you run "calicoctl ipam check --show-problem-ips" right after apply_new_cri task.
    Those ips are cleaned by calico garbage collector, but it can take about 20 minutes.
    This task releases problem ips with force.
    """
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    cluster.log.debug("Getting leaked ips...")
    random_report_name = "/tmp/%s.json" % uuid.uuid4().hex
    result = first_control_plane.sudo(f"calicoctl ipam check --show-problem-ips -o {random_report_name} | grep 'leaked' || true", is_async=False, hide=False)
    leaked_ips = result.get_simple_out()
    leaked_ips_count = leaked_ips.count('leaked')
    cluster.log.debug(f"Found {leaked_ips_count} leaked ips")
    if leaked_ips_count != 0:
        first_control_plane.sudo(f"calicoctl ipam release --from-report={random_report_name} --force", is_async=False, hide=False)
        cluster.log.debug("Leaked ips was released")
    first_control_plane.sudo(f"rm {random_report_name}", is_async=False, hide=False)
    

def edit_config(kubeadm_flags):
    kubeadm_flags = _config_changer(kubeadm_flags, "--container-runtime=remote")
    return _config_changer(kubeadm_flags,
                           "--container-runtime-endpoint=unix:///run/containerd/containerd.sock")


def _config_changer(config, word):
    equal_pos = word.find("=") + 1
    param_begin_pos = config.find(word[:equal_pos])
    if param_begin_pos != -1:
        param_end_pos = config[param_begin_pos:].find(" ")
        if param_end_pos == -1:
            return config[:param_begin_pos] + word + "\""
        return config[:param_begin_pos] + word + config[param_end_pos + param_begin_pos:]
    else:
        param_end_pos = config.rfind("\"")
        return config[:param_end_pos] + " " + word[:] + "\""


def migrate_cri_finalize_inventory(cluster, inventory_to_finalize):
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory_to_finalize
    finalize_functions = [
        _prepare_yum_repos,
        _prepare_packages,
        _prepare_crictl,
        _merge_containerd
    ]
    for finalize_fn in finalize_functions:
        cluster.log.verbose('Calling fn "%s"' % finalize_fn.__qualname__)
        inventory_to_finalize = finalize_fn(cluster, inventory_to_finalize, finalization=True)

    return inventory_to_finalize


tasks = OrderedDict({
    "add_repos": install.system_prepare_package_manager_configure,
    "apply_new_cri": migrate_cri,
    "release_calico_ipam_leacked_ips": release_calico_leaked_ips
})


class MigrateCRIAction(Action):
    def __init__(self):
        super().__init__('migrate cri', recreate_inventory=True)

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def main(cli_arguments=None):
    cli_help = '''
        Script for automated migration from docker to containerd.

        How to use:

        '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)
    context = flow.create_context(parser, cli_arguments, procedure="migrate_cri")

    flow.run_actions(context, [MigrateCRIAction()])


if __name__ == '__main__':
    main()
