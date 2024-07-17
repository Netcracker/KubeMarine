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

import itertools
from collections import OrderedDict
from typing import List, Callable, Dict
import uuid
from kubemarine import kubernetes, plugins, admission, jinja
from kubemarine.core import flow, log, resources as res
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes import components
from kubemarine.procedures import install


def cleanup_tmp_dir(cluster: KubernetesCluster) -> None:
    # Clean up kubernetes tmp dir, where backup files from previous upgrades are located
    nodes = cluster.make_group_from_roles(roles=["control-plane", "worker"])
    nodes.sudo("rm -rf $(sudo find /etc/kubernetes/tmp -mindepth 1 -maxdepth 1)")
    cluster.log.debug("Backup files for previous upgrades were cleaned")


def system_prepare_thirdparties(cluster: KubernetesCluster) -> None:
    if not cluster.inventory['services'].get('thirdparties', {}):
        cluster.log.debug("Skipped - no thirdparties defined in config file")
        return

    install.system_prepare_thirdparties(cluster)


def prepull_images(cluster: KubernetesCluster) -> None:
    cluster.log.debug("Prepulling Kubernetes images...")
    upgrade_group = kubernetes.get_group_for_upgrade(cluster)
    upgrade_group.call(kubernetes.images_grouped_prepull)


def kubernetes_upgrade(cluster: KubernetesCluster) -> None:
    initial_kubernetes_version = kubernetes.get_kubernetes_version(cluster.previous_inventory)

    upgrade_group = kubernetes.get_group_for_upgrade(cluster)
    preconfigure_components = []
    preconfigure_functions: Dict[str, Callable[[dict], dict]] = {}
    if (admission.is_pod_security_unconditional(cluster)
            and utils.version_key(initial_kubernetes_version)[0:2] < utils.minor_version_key("v1.28")
            and cluster.inventory['rbac']['pss']['pod-security'] == 'enabled'):

        # Extra args of API server have changed, need to reconfigure the API server.
        # See admission.enrich_inventory()
        # Still, should not reconfigure using generated ConfigMaps from inventory,
        # because the inventory has already incremented kubernetesVersion, but the cluster is not upgraded yet.
        # Instead, change only necessary apiServer args.
        def reconfigure_feature_gates(cluster_config: dict) -> dict:
            feature_gates = cluster.inventory["services"]["kubeadm"]["apiServer"]["extraArgs"].get("feature-gates")
            if feature_gates is not None:
                cluster_config["apiServer"]["extraArgs"]["feature-gates"] = feature_gates
            else:
                del cluster_config["apiServer"]["extraArgs"]["feature-gates"]

            return cluster_config

        preconfigure_components.append('kube-apiserver')
        preconfigure_functions['kubeadm-config'] = reconfigure_feature_gates

    if (kubernetes.components.kube_proxy_overwrites_higher_system_values(cluster)
            and utils.version_key(initial_kubernetes_version)[0:2] < utils.minor_version_key("v1.29")):

        # Defaults of KubeProxyConfiguration have changed.
        # See kubernetes.enrich_kube_proxy()
        def edit_kube_proxy_conntrack_min(kube_proxy_cm: dict) -> dict:
            expected_conntrack: dict = cluster.inventory['services']['kubeadm_kube-proxy']['conntrack']
            if 'min' not in expected_conntrack:
                return kube_proxy_cm

            actual_conntrack = kube_proxy_cm['conntrack']
            if expected_conntrack['min'] != actual_conntrack.get('min'):
                actual_conntrack['min'] = expected_conntrack['min']

            return kube_proxy_cm

        preconfigure_components.append('kube-proxy')
        preconfigure_functions['kube-proxy'] = edit_kube_proxy_conntrack_min

    if preconfigure_components:
        upgrade_group.call(kubernetes.components.reconfigure_components,
                           components=preconfigure_components, edit_functions=preconfigure_functions)

    drain_timeout = cluster.procedure_inventory.get('drain_timeout')
    grace_period = cluster.procedure_inventory.get('grace_period')
    disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)
    drain_kwargs = {
        'disable_eviction': disable_eviction, 'drain_timeout': drain_timeout, 'grace_period': grace_period
    }

    kubernetes.upgrade_first_control_plane(upgrade_group, cluster, **drain_kwargs)
    first_control_plane = cluster.nodes['control-plane'].get_first_member()

    # After first control-plane upgrade is finished we may loose our CoreDNS changes.
    # Thus, we need to re-apply our CoreDNS changes immediately after first control-plane upgrade.
    install.deploy_coredns(cluster)

    # In some versions, kubeadm reverts resolvConf to the default during `upgrade apply`
    # Remove default resolvConf from kubelet-config ConfigMap for debian OS family
    first_control_plane.call(components.patch_kubelet_configmap)

    kubernetes.upgrade_other_control_planes(upgrade_group, cluster, **drain_kwargs)

    if cluster.nodes.get('worker', []):
        kubernetes.upgrade_workers(upgrade_group, cluster, **drain_kwargs)

    kubernetes_cleanup_nodes_versions(cluster)


def kubernetes_cleanup_nodes_versions(cluster: KubernetesCluster) -> None:
    if not cluster.context.get('cached_nodes_versions_cleaned', False):
        cluster.log.verbose('Cached nodes versions required')
        cluster.nodes['control-plane'].get_first_member().sudo('rm -f /etc/kubernetes/nodes-k8s-versions.txt')
        cluster.context['cached_nodes_versions_cleaned'] = True
    else:
        cluster.log.verbose('Cached nodes versions already cleaned')


def upgrade_packages(cluster: KubernetesCluster) -> None:
    upgrade_version = kubernetes.get_procedure_upgrade_version(cluster)

    packages = cluster.procedure_inventory.get(upgrade_version, {}).get("packages", {})
    if packages.get("install") is not None or packages.get("upgrade") is not None or packages.get("remove") is not None:
        install.manage_custom_packages(cluster.nodes['all'])


def upgrade_plugins(cluster: KubernetesCluster) -> None:
    upgrade_version = kubernetes.get_procedure_upgrade_version(cluster)

    # upgrade_candidates is a source of upgradeable plugins, not list of plugins to upgrade.
    # Some plugins from upgrade_candidates will not be upgraded, because they have "install: false"
    upgrade_candidates = {}
    for plugin, plugin_item in cluster.inventory["plugins"].items():
        # Both OOB and custom plugins can have templates dependent on the inventory.
        # By default, let's do not re-install plugins if inventory does not change for them.
        #
        # Still there should be an ability to force re-install them with the same target inventory configuration,
        # using just empty spec in the procedure inventory.
        #
        # This requirement makes it impossible to turn off re-installation of OOB plugins,
        # if compatibility map changes, but target inventory does not (e.g. if all images are redefined).
        if (plugin in cluster.procedure_inventory.get(upgrade_version, {}).get("plugins", {})
                or cluster.previous_inventory["plugins"].get(plugin) != plugin_item):
            upgrade_candidates[plugin] = cluster.inventory["plugins"][plugin]

    plugins.install(cluster, upgrade_candidates)


def release_calico_leaked_ips(cluster: KubernetesCluster) -> None:
    """
    Sometimes IPs can stay in Calico IPAM despite not being used. 
    You can check this by running "calicoctl ipam check --show-problem-ips".
    Those IPs are cleaned by Calico garbage collector, but it can take about 20 minutes.
    This task releases problem IPs with force.
    """
    # Identify the first control plane node
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    cluster.log.debug("Getting leaked IPs...")

    # Generate a unique report name
    random_report_name = "/tmp/%s.json" % uuid.uuid4().hex
    try:
        # Run calicoctl ipam check and save the results
        first_control_plane.sudo(
            f"calicoctl ipam check --show-problem-ips -o {random_report_name} "
            "| grep 'leaked' || true", hide=False
        )
        cluster.log.debug(f"IPAM check completed and results saved to {random_report_name}")

        # Release the leaked IPs
        first_control_plane.sudo(
            f"calicoctl ipam release --from-report={random_report_name} --force", 
            hide=False
        )
    finally:
        # Clean up the temporary report file
        first_control_plane.sudo(f"rm {random_report_name}", hide=False)
        cluster.log.debug(f"Cleaned up report file: {random_report_name}")


tasks = OrderedDict({
    "cleanup_tmp_dir": cleanup_tmp_dir,
    "verify_upgrade_versions": kubernetes.verify_upgrade_versions,
    "thirdparties": system_prepare_thirdparties,
    "prepull_images": prepull_images,
    "kubernetes": kubernetes_upgrade,
    "kubernetes_cleanup": kubernetes_cleanup_nodes_versions,
    "packages": upgrade_packages,
    "plugins": upgrade_plugins,
    "release_calico_leaked_ips": release_calico_leaked_ips,  # Added here
    "overview": install.overview
})


class UpgradeFlow(flow.Flow):
    def __init__(self) -> None:
        self.target_version = "not supported"

    def _run(self, resources: DynamicResources) -> None:
        logger = resources.logger()

        previous_version = kubernetes.get_kubernetes_version(resources.inventory())
        upgrade_plan = resources.procedure_inventory().get('upgrade_plan')
        if not upgrade_plan:
            raise Exception('Upgrade plan is not specified in procedure')
        upgrade_plan = verify_upgrade_plan(previous_version, upgrade_plan, logger)

        args = resources.context['execution_arguments']
        if (args['tasks'] or args['exclude']) and len(upgrade_plan) > 1:
            raise Exception("Usage of '--tasks' and '--exclude' is not allowed when upgrading to more than one version")

        # todo inventory is preserved few times, probably need to preserve it once instead.
        actions = [UpgradeAction(version, i) for i, version in enumerate(upgrade_plan)]
        flow.run_actions(resources, actions)
        self.target_version = actions[-1].upgrade_version


class UpgradeAction(flow.TasksAction):
    def __init__(self, upgrade_version: str, upgrade_step: int) -> None:
        super().__init__(f'upgrade step {upgrade_step + 1}', tasks,
                         recreate_inventory=True)
        self.upgrade_version = upgrade_version
        self.upgrade_step = upgrade_step

        if upgrade_step > 0:
            del self.tasks['cleanup_tmp_dir']

    def cluster(self, res: DynamicResources) -> KubernetesCluster:
        # Make sure to enrich at DEFAULT stage without impact from changed context
        res.cluster(EnrichmentStage.DEFAULT)

        context = res.context
        context['upgrade_step'] = self.upgrade_step
        res.reset_cluster(EnrichmentStage.DEFAULT)
        # This starts PROCEDURE enrichment
        cluster = super().cluster(res)

        # New version is enriched and compiled
        self.upgrade_version = kubernetes.get_kubernetes_version(cluster.inventory)
        self.identifier = f'upgrade to {self.upgrade_version}'

        return cluster

    def run(self, resources: res.DynamicResources) -> None:
        super().run(resources)
        # Change context back, but do not DynamicResources.reset_cluster().
        # Once the inventory is recreated, the reset context will be picked up during new cluster initialization.
        del resources.context['upgrade_step']

    def prepare_context(self, context: dict) -> None:
        context['dump_subdir'] = 'upgrade' if jinja.is_template(self.upgrade_version) else self.upgrade_version


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for automated upgrade of the entire Kubernetes cluster to a new version.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='upgrade')
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow_ = UpgradeFlow()
    result = flow_.run_flow(context)

    kubernetes.verify_supported_version(flow_.target_version, result.logger)


def verify_upgrade_plan(previous_version: str, upgrade_plan: List[str], logger: log.EnhancedLogger) -> List[str]:
    # This validates upgrade possibility only partially, and lacks of CRI, PSP/PSS or other validations.
    # It could be better to run enrichment for all the versions before even one upgrade.
    is_any_template = False
    for version in itertools.chain((previous_version,), upgrade_plan):
        if not jinja.is_template(version):
            kubernetes.verify_allowed_version(version)
        else:
            is_any_template = True

    if not is_any_template:
        pv = previous_version
        for version in upgrade_plan:
            kubernetes.test_version_upgrade_possible(pv, version)
            pv = version

        logger.debug(f"Loaded upgrade plan: current ({previous_version}) ⭢ {' ⭢ '.join(upgrade_plan)}")
    else:
        logger.debug(f"Cannot early validate upgrade versions for jinja templates")

    return upgrade_plan


if __name__ == '__main__':
    main()
