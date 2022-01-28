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
from io import StringIO

import yaml
import toml

from distutils.util import strtobool
from kubemarine.core.flow import load_inventory
from kubemarine.core.yaml_merger import default_merger
from kubemarine.core import flow
from kubemarine.procedures import install
from kubemarine import kubernetes, plugins, system
from itertools import chain
from kubemarine.core import utils
from kubemarine.core.executor import RemoteExecutor






def system_prepare_thirdparties(cluster):
    if not cluster.inventory['services'].get('thirdparties', {}):
        cluster.log.debug("Skipped - no thirdparties defined in config file")
        return

    install.system_prepare_thirdparties(cluster)


def prepull_images(cluster):
    cluster.log.debug("Prepulling Kubernetes images...")
    fix_cri_socket(cluster)
    upgrade_group = kubernetes.get_group_for_upgrade(cluster)
    upgrade_group.call(kubernetes.images_grouped_prepull)


def kubernetes_upgrade(cluster):
    version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
    upgrade_group = kubernetes.get_group_for_upgrade(cluster)

    drain_timeout = cluster.procedure_inventory.get('drain_timeout')
    grace_period = cluster.procedure_inventory.get('grace_period')

    kubernetes.upgrade_first_master(version, upgrade_group, cluster,
                                    drain_timeout=drain_timeout, grace_period=grace_period)

    # After first master upgrade is finished we may loose our CoreDNS changes.
    # Thus, we need to re-apply our CoreDNS changes immediately after first master upgrade.
    install.deploy_coredns(cluster)

    kubernetes.upgrade_other_masters(version, upgrade_group, cluster,
                                     drain_timeout=drain_timeout, grace_period=grace_period)
    if cluster.nodes.get('worker', []):
        kubernetes.upgrade_workers(version, upgrade_group, cluster,
                                   drain_timeout=drain_timeout, grace_period=grace_period)

    cluster.nodes['master'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt')
    cluster.context['cached_nodes_versions_cleaned'] = True


def kubernetes_cleanup_nodes_versions(cluster):
    if not cluster.context.get('cached_nodes_versions_cleaned', False):
        cluster.log.verbose('Cached nodes versions required')
        cluster.nodes['master'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt')
    else:
        cluster.log.verbose('Cached nodes versions already cleaned')


def upgrade_packages(cluster):
    upgrade_version = cluster.context["upgrade_version"]

    packages = cluster.procedure_inventory.get(upgrade_version, {}).get("packages", {})
    if packages.get("install") or packages.get("upgrade") or packages.get("remove"):
        install.system_prepare_package_manager_manage_packages(cluster)


def upgrade_plugins(cluster):
    upgrade_version = cluster.context["upgrade_version"]

    # upgrade_candidates is a source of upgradeable plugins, not list of plugins to upgrade.
    # Some plugins from upgrade_candidates will not be upgraded, because they have "install: false"
    upgrade_candidates = {}
    defined_plugins = cluster.procedure_inventory.get(upgrade_version, {}).get("plugins", {}).keys()
    for plugin in chain(defined_plugins, plugins.oob_plugins):
        # TODO: use only OOB plugins that have changed version so that we do not perform redundant installations
        upgrade_candidates[plugin] = cluster.inventory["plugins"][plugin]

    plugins.install(cluster, upgrade_candidates)


def upgrade_containerd(cluster):

    target_kubernetes_version = cluster.context["upgrade_version"]
    index = target_kubernetes_version.rfind(".")
    target_kubernetes_version = target_kubernetes_version[:index]
    pause_version = cluster.globals['compatibility_map']['software']['pause'][target_kubernetes_version]['version']
    path = 'plugins."io.containerd.grpc.v1.cri"'
    last_pause_version = cluster.inventory["services"]["cri"]['containerdConfig'][path]["sandbox_image"].split(":")[2]
    if last_pause_version != pause_version:
        sandbox = cluster.inventory["services"]["cri"]['containerdConfig'][path]["sandbox_image"]
        param_begin_pos = sandbox.rfind(":")
        sandbox = sandbox[:param_begin_pos] + ":" + str(pause_version)
        cluster.inventory["services"]["cri"]['containerdConfig'][path]["sandbox_image"] = sandbox
        config_string = ""
        containerd_config = cluster.inventory["services"]["cri"]['containerdConfig']
        runc_options_path = 'plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options'
        if not isinstance(containerd_config[runc_options_path]['SystemdCgroup'], bool):
            containerd_config[runc_options_path]['SystemdCgroup'] = \
                bool(strtobool(containerd_config[runc_options_path]['SystemdCgroup']))
        for key, value in containerd_config.items():
            # first we process all "simple" `key: value` pairs
            if not isinstance(value, dict):
                config_string += f"{toml.dumps({key: value})}"
        for key, value in containerd_config.items():
            # next we process all "complex" `key: dict_value` pairs, representing named sections
            if isinstance(value, dict):
                config_string += f"\n[{key}]\n{toml.dumps(value)}"
        config_toml = toml.loads(config_string)
        utils.dump_file(cluster, config_string, 'containerd-config.toml')
        with RemoteExecutor(cluster) as exe:
            for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
                os_specific_associations = cluster.get_associations_for_node(node['connect_to'])['containerd']
                node['connection'].put(StringIO(config_string), os_specific_associations['config_location'],
                                       backup=True,
                                       sudo=True, mkdir=True)
                node['connection'].sudo(f"chmod 600 {os_specific_associations['config_location']} && "
                                        f"sudo systemctl restart {os_specific_associations['service_name']} && "
                                        f"systemctl status {os_specific_associations['service_name']}")
        return exe.get_last_results_str()


tasks = OrderedDict({
    "verify_upgrade_versions": kubernetes.verify_upgrade_versions,
    "thirdparties": system_prepare_thirdparties,
    "prepull_images": prepull_images,
    "kubernetes": kubernetes_upgrade,
    "kubernetes_cleanup": kubernetes_cleanup_nodes_versions,
    "packages": upgrade_packages,
    "upgrade_containerd": upgrade_containerd,
    "plugins": upgrade_plugins,
    "overview": install.overview

})


def upgrade_finalize_inventory(cluster, inventory):
    if cluster.context.get("initial_procedure") != "upgrade":
        return inventory
    upgrade_version = cluster.context.get("upgrade_version")

    if not inventory['services'].get('kubeadm'):
        inventory['services']['kubeadm'] = {}
    inventory['services']['kubeadm']['kubernetesVersion'] = upgrade_version

    # if thirdparties was not defined in procedure.yaml,
    # then no need to forcibly place them: user may want to use default
    if cluster.procedure_inventory.get(upgrade_version, {}).get('thirdparties'):
        inventory['services']['thirdparties'] = cluster.procedure_inventory[upgrade_version]['thirdparties']

    if cluster.procedure_inventory.get(upgrade_version, {}).get("plugins"):
        if not inventory.get("plugins"):
            inventory["plugins"] = {}
        default_merger.merge(inventory["plugins"], cluster.procedure_inventory[upgrade_version]["plugins"])

    if cluster.procedure_inventory.get(upgrade_version, {}).get("packages"):
        if not inventory.get("services"):
            inventory["services"] = {}
        if not inventory["services"].get("packages"):
            inventory["services"]["packages"] = {}
        packages = cluster.procedure_inventory[upgrade_version]["packages"]
        default_merger.merge(inventory["services"]["packages"], packages)

    return inventory


def main(cli_arguments=None):
    cli_help = '''
    Script for automated upgrade of the entire Kubernetes cluster to a new version.

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

    with open(args.procedure_config, 'r') as stream:
        procedure_config = yaml.safe_load(stream)

    os_family = preload_os_family(args.config)
    upgrade_plan = verify_upgrade_plan(procedure_config.get('upgrade_plan'))
    verification_version_result = kubernetes.verify_target_version(upgrade_plan[-1])

    if (args.tasks or args.exclude) and len(upgrade_plan) > 1:
        raise Exception("Usage of '--tasks' and '--exclude' is not allowed when upgrading to more than one version")

    # We need to save dumps for all iterations, so we forcefully disable dump cleanup after first iteration onwards.
    disable_dump_cleanup = False
    for version in upgrade_plan:

        # reset context from previous installation
        context = flow.create_context(args, procedure='upgrade',
                                      included_tasks=defined_tasks, excluded_tasks=defined_excludes)
        context['inventory_regenerate_required'] = True
        context['upgrade_version'] = version
        context['dump_filename_prefix'] = version
        context['os'] = os_family
        if disable_dump_cleanup:
            context['execution_arguments']['disable_dump_cleanup'] = True

        flow.run(
            tasks,
            defined_tasks,
            defined_excludes,
            args.config,
            context,
            procedure_inventory_filepath=args.procedure_config,
            cumulative_points=install.cumulative_points
        )

        disable_dump_cleanup = True
    if verification_version_result:
        print(verification_version_result)


def verify_upgrade_plan(upgrade_plan):
    if not upgrade_plan:
        raise Exception('Upgrade plan is not specified or empty')

    upgrade_plan.sort()

    previous_version = None
    for i in range(0, len(upgrade_plan)):
        version = upgrade_plan[i]
        if previous_version is not None:
            kubernetes.test_version_upgrade_possible(previous_version, version)
        previous_version = version

    print('Loaded upgrade plan: current ⭢', ' ⭢ '.join(upgrade_plan))

    return upgrade_plan


def preload_os_family(inventory_filepath):
    cluster = load_inventory(inventory_filepath, flow.create_context({'disable_dump': True}))
    return system.get_os_family(cluster)


def fix_cri_socket(cluster):
    """
    This method fixs the issue with 'kubeadm.alpha.kubernetes.io/cri-socket' node annotation
    and delete the docker socket if it exists
    """

    if cluster.inventory["services"]["cri"]["containerRuntime"] == "containerd":
        master = cluster.nodes["master"].get_first_member(provide_node_configs=True)
        master["connection"].sudo(f"sudo kubectl annotate nodes --all \
                                     --overwrite kubeadm.alpha.kubernetes.io/cri-socket=/run/containerd/containerd.sock"
                                     , is_async=False, hide=True)
        upgrade_group = kubernetes.get_group_for_upgrade(cluster)
        upgrade_group.sudo("rm -rf /var/run/docker.sock")


if __name__ == '__main__':
    main()
