#!/usr/bin/env python3

from collections import OrderedDict

import io
import ruamel.yaml

from kubetool import kubernetes
from kubetool.core import flow
from kubetool.cri import docker
from kubetool.procedures import install
from kubetool.core.yaml_merger import default_merger
from kubetool import packages


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


def configure_containerd_on_nodes(cluster):
    install.system_cri_install(cluster)
    install.system_cri_configure(cluster)
    install.system_prepare_thirdparties(cluster)


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
    _migrate_cri(cluster, cluster.nodes["master"].get_ordered_members_list(provide_node_configs=True))
    _migrate_cri(cluster, cluster.nodes["worker"].exclude_group(cluster.nodes["master"])
                 .get_ordered_members_list(provide_node_configs=True))


def _migrate_cri(cluster, node_group):
    """
    Migrate CRI from docker to already installed containerd.
    This method works node-by-node, configuring kubelet to use containerd.
    :param cluster: main object describing a cluster
    :param node_group: group of nodes to migrate
    """

    for node in node_group:
        if "master" in node["roles"]:
            master = node
        else:
            master = cluster.nodes["master"].get_first_member(provide_node_configs=True)

        version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
        cluster.log.debug("Upgrading \"%s\"" % node["name"])
        disable_eviction = True
        drain_cmd = kubernetes.prepare_drain_command(node, version, cluster.globals, disable_eviction, cluster.nodes)
        master["connection"].sudo(drain_cmd, is_async=False, hide=False)
        # `kubectl drain` ignores system pods, delete them explicitly
        if "master" in node["roles"]:
            node["connection"].sudo(f"kubectl -n kube-system delete pod etcd-{node['name']} "
                                    f"kube-apiserver-{node['name']} "
                                    f"kube-controller-manager-{node['name']} "
                                    f"kube-scheduler-{node['name']} "
                                    f"$(sudo kubectl describe node {node['name']} | \
                                        grep -E 'kube-system\s+kube-proxy-[a-z,0-9]{{5}}' | awk '{{print $2}}')"
                                    , is_async=False, hide=False).get_simple_out()

        kubeadm_flags_file = "/var/lib/kubelet/kubeadm-flags.env"
        kubeadm_flags = node["connection"].sudo(f"cat {kubeadm_flags_file}",
                                                is_async=False).get_simple_out()

        kubeadm_flags = edit_config(kubeadm_flags)

        node["connection"].put(io.StringIO(kubeadm_flags), kubeadm_flags_file, backup=True, sudo=True)

        node["connection"].sudo("systemctl stop kubelet")
        docker.prune(node["connection"])
        docker_associations = cluster.get_associations_for_node(node['connect_to'])['docker']
        node["connection"].sudo(f"systemctl disable {docker_associations['service_name']} --now;"
                                 "sudo sh -c 'rm -rf /var/lib/docker/*'")

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
        master["connection"].sudo(f"sudo kubectl uncordon {node['name']}", is_async=False, hide=False)
        if "master" in node["roles"]:
            kubernetes.wait_for_any_pods(cluster, node["connection"], apply_filter=node["name"])

        packages_list = []
        for package_name in docker_associations['package_name']:
            if not package_name.startswith('containerd'):
                packages_list.append(package_name)
        cluster.log.warning("The following packages will be removed: %s" % packages_list)
        packages.remove(node["connection"], include=packages_list)

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
    "configure_containerd_on_nodes": configure_containerd_on_nodes,
    "apply_new_cri": migrate_cri,
})


def main(cli_arguments=None):
    cli_help = '''
        Script for automated migration from docker to containerd.

        How to use:

        '''

    parser = flow.new_parser(cli_help)
    parser.add_argument('--tasks',
                        default='',
                        help='define comma-separated tasks to be executed')

    parser.add_argument('--exclude',
                        default='',
                        help='exclude comma-separated tasks from execution')

    parser.add_argument('procedure_config', metavar='procedure_config', type=str,
                        help='config file for upgrade parameters')

    if cli_arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cli_arguments)

    defined_tasks = []
    defined_excludes = []

    if args.tasks != '':
        defined_tasks = args.tasks.split(",")

    if args.exclude != '':
        defined_excludes = args.exclude.split(",")

    context = flow.create_context(args, procedure="migrate_cri",
                                  included_tasks=defined_tasks, excluded_tasks=defined_excludes)
    context["inventory_regenerate_required"] = True

    flow.run(
        tasks,
        defined_tasks,
        defined_excludes,
        args.config,
        context,
        procedure_inventory_filepath=args.procedure_config,
        cumulative_points=install.cumulative_points
    )


if __name__ == '__main__':
    main()
