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

from kubemarine import kubernetes, etcd, thirdparties, cri
from kubemarine.core import flow, resources
from kubemarine.core.action import Action
from kubemarine.cri import docker
from kubemarine.procedures import install
from kubemarine.core.yaml_merger import default_merger
from kubemarine import packages


def enrich_inventory(inventory, cluster):
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory
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


def _prepare_yum_repos(cluster, inventory):
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


def _prepare_packages(cluster, inventory):
    if not cluster.procedure_inventory.get("packages", {}):
        cluster.log.debug("Skipped - no packages defined in procedure config file")
        return inventory

    if not cluster.procedure_inventory["packages"].get("associations", {}):
        cluster.log.debug("Skipped - no associations defined in procedure config file")
        return inventory

    if not inventory["services"].get("packages", {}):
        inventory["services"]["packages"] = {}

    if inventory["services"]["packages"].get("associations", {}):
        default_merger.merge(inventory["services"]["packages"]["associations"],
                             cluster.procedure_inventory["packages"]["associations"])
    else:
        inventory["services"]["packages"]["associations"] = cluster.procedure_inventory["packages"]["associations"]
    return inventory


def _prepare_crictl(cluster, inventory):
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


def _configure_containerd_on_nodes(cluster, inventory):
    if "cri" not in cluster.procedure_inventory or "containerRuntime" not in cluster.procedure_inventory["cri"]:
        raise Exception("Please specify mandatory parameter cri.containerRuntime in procedure.yaml")

    if cluster.procedure_inventory["cri"]["containerRuntime"] != "containerd":
        raise Exception("Migration could be possible only to containerd")

    if inventory["services"]["cri"]["containerRuntime"] == cluster.procedure_inventory["cri"]["containerRuntime"]:
        raise Exception("You already have such cri or you should explicitly specify 'cri.containerRuntime: docker' in cluster.yaml")

    inventory = _merge_containerd(cluster, inventory)
    return inventory


def _merge_containerd(cluster, inventory):
    if not inventory["services"].get("cri", {}):
        inventory["services"]["cri"] = {}

    if inventory["services"]["cri"].get("dockerConfig", {}):
        del inventory["services"]["cri"]["dockerConfig"]

    default_merger.merge(inventory["services"]["cri"], cluster.procedure_inventory["cri"])
    return inventory


def migrate_cri(cluster):
    _migrate_cri(cluster, cluster.nodes["control-plane"].get_ordered_members_list(provide_node_configs=True))
    _migrate_cri(cluster, cluster.nodes["worker"].exclude_group(cluster.nodes["control-plane"])
                 .get_ordered_members_list(provide_node_configs=True))


def _migrate_cri(cluster, node_group):
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
        control-plane["connection"].sudo(drain_cmd, is_async=False, hide=False)
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

        docker_associations = cluster.get_associations_for_node(node['connect_to'])['docker']
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
                                # start kubelet
                                "sudo systemctl restart kubelet")
        control-plane["connection"].sudo(f"sudo kubectl uncordon {node['name']}", is_async=False, hide=False)
        if "control-plane" in node["roles"]:
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
        control-plane["connection"].sudo(f"sudo kubectl annotate node {node['name']} "
                                  f"--overwrite kubeadm.alpha.kubernetes.io/cri-socket=/run/containerd/containerd.sock",
                                  is_async=False, hide=True)

        # delete docker socket
        node["connection"].sudo("rm -rf /var/run/docker.sock", hide=False)


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
        inventory_to_finalize = finalize_fn(cluster, inventory_to_finalize)

    return inventory_to_finalize


tasks = OrderedDict({
    "add_repos": install.system_prepare_package_manager_configure,
    "apply_new_cri": migrate_cri,
})


class MigrateCRIAction(Action):
    def __init__(self):
        super().__init__('migrate cri', recreate_inventory=True)

    def run(self, res: 'resources.DynamicResources'):
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def main(cli_arguments=None):
    cli_help = '''
        Script for automated migration from docker to containerd.

        How to use:

        '''

    parser = flow.new_procedure_parser(cli_help)

    args = flow.parse_args(parser, cli_arguments)
    context = flow.create_context(args, procedure="migrate_cri")

    flow.run_actions(context, [MigrateCRIAction()])


if __name__ == '__main__':
    main()
