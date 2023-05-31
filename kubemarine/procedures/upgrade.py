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
from distutils.util import strtobool
from io import StringIO
from itertools import chain
from typing import List

import toml

from kubemarine import kubernetes, plugins
from kubemarine.core import flow
from kubemarine.core import utils
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install


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
    upgrade_group = kubernetes.get_group_for_upgrade(cluster)

    drain_timeout = cluster.procedure_inventory.get('drain_timeout')
    grace_period = cluster.procedure_inventory.get('grace_period')
    disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)
    drain_kwargs = {
        'disable_eviction': disable_eviction, 'drain_timeout': drain_timeout, 'grace_period': grace_period
    }

    kubernetes.upgrade_first_control_plane(upgrade_group, cluster, **drain_kwargs)

    # After first control-plane upgrade is finished we may loose our CoreDNS changes.
    # Thus, we need to re-apply our CoreDNS changes immediately after first control-plane upgrade.
    install.deploy_coredns(cluster)

    kubernetes.upgrade_other_control_planes(upgrade_group, cluster, **drain_kwargs)

    if cluster.nodes.get('worker', []):
        kubernetes.upgrade_workers(upgrade_group, cluster, **drain_kwargs)

    cluster.nodes['control-plane'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt')
    cluster.context['cached_nodes_versions_cleaned'] = True


def kubernetes_cleanup_nodes_versions(cluster):
    if not cluster.context.get('cached_nodes_versions_cleaned', False):
        cluster.log.verbose('Cached nodes versions required')
        cluster.nodes['control-plane'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt')
    else:
        cluster.log.verbose('Cached nodes versions already cleaned')
    kubernetes_apply_taints(cluster)


def upgrade_packages(cluster: KubernetesCluster):
    upgrade_version = cluster.context["upgrade_version"]

    packages = cluster.procedure_inventory.get(upgrade_version, {}).get("packages", {})
    if packages.get("install") is not None or packages.get("upgrade") is not None or packages.get("remove") is not None:
        install.manage_custom_packages(cluster.nodes['all'])


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


def upgrade_containerd(cluster: KubernetesCluster):
    """
        This function fixes the incorrect version of pause during the cluster update procedure
    """

    cri = cluster.inventory["services"]["cri"]['containerRuntime']
    if cri == 'containerd':
        path = 'plugins."io.containerd.grpc.v1.cri"'
        target_kubernetes_version = cluster.context["upgrade_version"]
        pause_version = cluster.globals['compatibility_map']['software']['pause'][target_kubernetes_version]['version']
        if not cluster.inventory["services"]["cri"]['containerdConfig'].get(path, False):
            return
        last_pause_version = cluster.inventory["services"]["cri"]['containerdConfig'][path]["sandbox_image"].split(":")[
            2]
        if True:
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
            utils.dump_file(cluster, config_string, 'containerd-config.toml')
            with RemoteExecutor(cluster) as exe:
                for node in cluster.nodes['control-plane'].include_group(
                        cluster.nodes.get('worker')).get_ordered_members_list(
                        provide_node_configs=True):
                    os_specific_associations = cluster.get_associations_for_node(node['connect_to'], 'containerd')
                    node['connection'].put(StringIO(config_string), os_specific_associations['config_location'],
                                           backup=True,
                                           sudo=True, mkdir=True)
                    node['connection'].sudo(f"sudo systemctl restart {os_specific_associations['service_name']} && "
                                            f"systemctl status {os_specific_associations['service_name']}")
            return exe.get_last_results_str()


tasks = OrderedDict({
    "verify_upgrade_versions": kubernetes.verify_upgrade_versions,
    "thirdparties": system_prepare_thirdparties,
    "prepull_images": prepull_images,
    "configure_policy": install.system_prepare_policy,
    "kubernetes": kubernetes_upgrade,
    "kubernetes_cleanup": kubernetes_cleanup_nodes_versions,
    "packages": upgrade_packages,
    "upgrade_containerd": upgrade_containerd,
    "plugins": upgrade_plugins,
    "overview": install.overview

})


class UpgradeFlow(flow.Flow):
    def __init__(self):
        self.target_version = None

    def _run(self, resources: DynamicResources):
        logger = resources.logger()

        previous_version = kubernetes.get_initial_kubernetes_version(resources.raw_inventory())
        upgrade_plan = resources.procedure_inventory().get('upgrade_plan')
        upgrade_plan = verify_upgrade_plan(previous_version, upgrade_plan)
        logger.debug(f"Loaded upgrade plan: current ({previous_version}) ⭢ {' ⭢ '.join(upgrade_plan)}")

        self.target_version = upgrade_plan[-1]
        kubernetes.verify_supported_version(self.target_version, logger)

        args = resources.context['execution_arguments']
        if (args['tasks'] or args['exclude']) and len(upgrade_plan) > 1:
            raise Exception("Usage of '--tasks' and '--exclude' is not allowed when upgrading to more than one version")

        # todo inventory is preserved few times, probably need to preserve it once instead.
        actions = [UpgradeAction(version) for version in upgrade_plan]
        flow.run_actions(resources, actions)


class UpgradeAction(Action):
    def __init__(self, upgrade_version: str):
        super().__init__('upgrade to ' + upgrade_version, recreate_inventory=True)
        self.upgrade_version = upgrade_version

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)
        res.make_final_inventory()

    def prepare_context(self, context: dict) -> None:
        context['upgrade_version'] = self.upgrade_version
        context['dump_filename_prefix'] = self.upgrade_version


def main(cli_arguments=None):
    cli_help = '''
    Script for automated upgrade of the entire Kubernetes cluster to a new version.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='upgrade')
    flow_ = UpgradeFlow()
    result = flow_.run_flow(context)

    kubernetes.verify_supported_version(flow_.target_version, result.logger)


def verify_upgrade_plan(previous_version: str, upgrade_plan: List[str]):
    kubernetes.verify_allowed_version(previous_version)
    for version in upgrade_plan:
        kubernetes.verify_allowed_version(version)

    upgrade_plan.sort(key=utils.version_key)

    for version in upgrade_plan:
        kubernetes.test_version_upgrade_possible(previous_version, version)
        previous_version = version

    return upgrade_plan


def fix_cri_socket(cluster):
    """
    This method fixs the issue with 'kubeadm.alpha.kubernetes.io/cri-socket' node annotation
    and delete the docker socket if it exists
    """

    if cluster.inventory["services"]["cri"]["containerRuntime"] == "containerd":
        control_plane = cluster.nodes["control-plane"].get_first_member(provide_node_configs=True)
        control_plane["connection"].sudo(f"sudo kubectl annotate nodes --all \
                                     --overwrite kubeadm.alpha.kubernetes.io/cri-socket=/run/containerd/containerd.sock"
                                         , is_async=False, hide=True)
        upgrade_group = kubernetes.get_group_for_upgrade(cluster)
        upgrade_group.sudo("rm -rf /var/run/docker.sock")


def kubernetes_apply_taints(cluster):
    # Apply taints after upgrade
    group = cluster.nodes['control-plane']
    kubernetes.apply_taints(group)


if __name__ == '__main__':
    main()
