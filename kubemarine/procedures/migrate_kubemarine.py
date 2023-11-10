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
import argparse
import re
from abc import ABC, abstractmethod
from textwrap import dedent
from typing import List, Union

import yaml

import kubemarine.patches
from kubemarine import kubernetes, plugins, cri, packages, etcd, thirdparties, haproxy, keepalived
from kubemarine.core import flow, static, utils, errors
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.patch import Patch, _SoftwareUpgradePatch
from kubemarine.core.resources import DynamicResources

SOFTWARE_UPGRADE_PATH = utils.get_internal_resource_path("patches/software_upgrade.yaml")


class SoftwareUpgradeAction(Action, ABC):
    def __init__(self, software_name: str, k8s_versions: List[str]) -> None:
        super().__init__(f'Upgrade {software_name}')
        self.software_name = software_name
        self.k8s_versions = k8s_versions

    def run(self, res: DynamicResources) -> None:
        # We should not call DynamicResources.cluster() and should only access the raw inventory,
        # because otherwise enrichment will start with probably not relevant validation.
        version = kubernetes.get_initial_kubernetes_version(res.raw_inventory())
        if version not in self.k8s_versions:
            res.logger().info(f"Patch is not relevant for Kubernetes {version}")
            return

        self.specific_run(res)
        res.make_final_inventory()

    @abstractmethod
    def specific_run(self, res: DynamicResources) -> None:
        pass


class ThirdpartyUpgradeAction(SoftwareUpgradeAction):
    def __init__(self, software_name: str, k8s_versions: List[str]) -> None:
        super().__init__(software_name, k8s_versions)
        self._destination = thirdparties.get_thirdparty_destination(self.software_name)

    def specific_run(self, res: DynamicResources) -> None:
        logger = res.logger()
        cluster = res.cluster()
        if self._destination not in cluster.inventory['services']['thirdparties']:
            version = kubernetes.get_initial_kubernetes_version(cluster.inventory)
            cri_impl = cri.get_initial_cri_impl(cluster.inventory)
            logger.info(f"Patch is not relevant for Kubernetes {version}, based on {cri_impl}")
            return

        self.recreate_inventory = True
        logger.info(f"Reinstalling third-party {self._destination!r}")
        self._run(cluster)

    def _run(self, cluster: KubernetesCluster) -> None:
        thirdparties.install_thirdparty(cluster.nodes['all'], self._destination)

    def prepare_context(self, context: dict) -> None:
        context['upgrading_thirdparty'] = self._destination

    def reset_context(self, context: dict) -> None:
        del context['upgrading_thirdparty']


class CriUpgradeAction(Action):
    def __init__(self, upgrade_config: dict) -> None:
        super().__init__(f'Upgrade CRI')
        self.upgrade_config = upgrade_config

    def run(self, res: DynamicResources) -> None:
        # Access only to raw inventory to prepare context
        cri_impl = cri.get_initial_cri_impl(res.raw_inventory())
        res.context['upgrading_package'] = cri_impl

        if not self.associations_changed(res):
            return

        # Only now the cluster is initialized and full enrichment is run.
        cluster = res.cluster()
        if cri_impl not in cluster.context["upgrade"]["required"]['packages']:
            res.logger().info(f"Nothing has changed in associations of {cri_impl!r}. Upgrade is not required.")
            return

        self.recreate_inventory = True
        self._run(cluster)

        res.make_final_inventory()

    def reset_context(self, context: dict) -> None:
        del context['upgrading_package']

    def _run(self, cluster: KubernetesCluster) -> None:
        if 'worker' in cluster.nodes:
            self.upgrade_cri(cluster.nodes["worker"].exclude_group(cluster.nodes["control-plane"]), workers=True)
        self.upgrade_cri(cluster.nodes["control-plane"], workers=False)

    def upgrade_cri(self, group: NodeGroup, workers: bool) -> None:
        cluster: KubernetesCluster = group.cluster

        drain_timeout = cluster.procedure_inventory.get('drain_timeout')
        grace_period = cluster.procedure_inventory.get('grace_period')
        disable_eviction = cluster.procedure_inventory.get("disable-eviction", True)

        for node in group.get_ordered_members_list():
            node_name = node.get_node_name()
            control_plane = node
            if workers:
                control_plane = cluster.nodes["control-plane"].get_first_member()

            drain_cmd = kubernetes.prepare_drain_command(
                cluster, node_name,
                disable_eviction=disable_eviction, drain_timeout=drain_timeout, grace_period=grace_period)
            control_plane.sudo(drain_cmd, hide=False)

            kubernetes.upgrade_cri_if_required(node)
            node.sudo('systemctl restart kubelet')

            if workers:
                control_plane.sudo(f"kubectl uncordon {node_name}", hide=False)
            else:
                kubernetes.wait_uncordon(node)

            if not workers:
                kubernetes.wait_for_any_pods(cluster, node, apply_filter=node_name)
                etcd.wait_for_health(cluster, node)

    def associations_changed(self, res: DynamicResources) -> bool:
        """
        Detects if upgrade is required for the given Kubernetes version, OS family and CRI implementation.
        The method should not run full enrichment, and run only light enrichment to detect OS family.
        """
        version = kubernetes.get_initial_kubernetes_version(res.raw_inventory())
        cri_impl = cri.get_initial_cri_impl(res.raw_inventory())

        nodes_context = res.get_nodes_context()
        os_families = list({ctx['os']['family'] for ctx in nodes_context.values()})
        if len(os_families) != 1 or os_families[0] not in packages.get_associations_os_family_keys():
            raise errors.KME("KME0012")
        os_family = os_families[0]
        version_key = packages.get_compatibility_version_key(os_family)

        changes_detected = False
        packages_names = static.GLOBALS['packages'][os_family][cri_impl]['package_name']
        for kv in packages_names:
            software_name = list(kv.values())[0]
            kubernetes_upgrade_list = self.upgrade_config['packages'][software_name][version_key]
            changes_detected = changes_detected or version in kubernetes_upgrade_list

        if not changes_detected:
            res.logger().info(f"Patch is not relevant for Kubernetes {version}, "
                              f"based on {cri_impl} and {os_family!r} OS family")

        return changes_detected


class BalancerUpgradeAction(Action):
    def __init__(self, upgrade_config: dict, package_name: str) -> None:
        super().__init__(f'Upgrade {package_name}')
        self.upgrade_config = upgrade_config
        self.package_name = package_name

    def run(self, res: DynamicResources) -> None:
        if not self.associations_changed(res):
            return

        # Only now the cluster is initialized and full enrichment is run.
        cluster = res.cluster()
        logger = res.logger()
        if self.package_name not in cluster.context["upgrade"]["required"]['packages']:
            logger.info(f"Nothing has changed in associations of {self.package_name!r}. Upgrade is not required.")
            return

        role = 'balancer' if self.package_name == 'haproxy' else 'keepalived'
        group = cluster.make_group_from_roles([role])
        if group.is_empty():
            logger.info(f"No nodes to install {self.package_name!r}.")
            return

        logger.info(f"Reinstalling {self.package_name} on nodes: {group.get_nodes_names()}")
        self.recreate_inventory = True

        self._run(group)
        res.make_final_inventory()

    def _run(self, group: NodeGroup) -> None:
        cluster: KubernetesCluster = group.cluster
        packages.install(group, include=cluster.get_package_association(self.package_name, 'package_name'))
        if self.package_name == 'haproxy':
            haproxy.restart(group)
        else:
            keepalived.restart(group)

    def associations_changed(self, res: DynamicResources) -> bool:
        """
        Detects if upgrade is required for the given OS family.
        The method should not run full enrichment, and run only light enrichment to detect OS family.
        """
        nodes_context = res.get_nodes_context()
        os_families = list({ctx['os']['family'] for ctx in nodes_context.values()})
        if len(os_families) != 1 or os_families[0] not in packages.get_associations_os_family_keys():
            raise errors.KME("KME0012")
        os_family = os_families[0]
        version_key = packages.get_compatibility_version_key(os_family)

        changes_detected: Union[List[str], bool] = self.upgrade_config['packages'][self.package_name][version_key]
        if not changes_detected:
            res.logger().info(f"Patch is not relevant for {os_family!r} OS family")

        return bool(changes_detected)

    def prepare_context(self, context: dict) -> None:
        context['upgrading_package'] = self.package_name

    def reset_context(self, context: dict) -> None:
        del context['upgrading_package']


class PluginUpgradeAction(SoftwareUpgradeAction):
    def specific_run(self, res: DynamicResources) -> None:
        self.recreate_inventory = True

        cluster = res.cluster()
        # TODO despite that we are sure that the recommended version has changed,
        #  upgrade might still be not required if the effective configuration did not change.
        upgrade_candidates = {
            self.software_name: cluster.inventory['plugins'][self.software_name]
        }
        self._run(cluster, upgrade_candidates)

    def _run(self, cluster: KubernetesCluster, upgrade_candidates: dict) -> None:
        plugins.install(cluster, upgrade_candidates)

    def prepare_context(self, context: dict) -> None:
        context['upgrading_plugin'] = self.software_name
        if self.software_name == 'calico':
            context['upgrading_thirdparty'] = thirdparties.get_thirdparty_destination('calicoctl')

    def reset_context(self, context: dict) -> None:
        del context['upgrading_plugin']
        if self.software_name == 'calico':
            del context['upgrading_thirdparty']


class ThirdpartyUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, thirdparty_name: str, k8s_versions: List[str]) -> None:
        super().__init__(f"upgrade_{thirdparty_name}")
        self.thirdparty_name = thirdparty_name
        self.k8s_versions = k8s_versions

    @property
    def action(self) -> Action:
        return ThirdpartyUpgradeAction(self.thirdparty_name, self.k8s_versions)

    @property
    def description(self) -> str:
        versions_list = '\n'.join(f" - {ver}" for ver in self.k8s_versions)

        return dedent(
            f"""\
            Upgrade {self.thirdparty_name!r} for the following Kubernetes versions:
            {{versions_list}}
            Roughly equivalent to 'kubemarine install --tasks=prepare.thirdparties'
            provided that all third-parties except the {self.thirdparty_name!r} are already actual.
            """.rstrip()
        ).format(versions_list=versions_list)


class CriUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, upgrade_config: dict) -> None:
        super().__init__(f"upgrade_cri")
        self.upgrade_config = upgrade_config

    @property
    def action(self) -> Action:
        return CriUpgradeAction(self.upgrade_config)

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Upgrade CRI for necessary Kubernetes versions with particular CRI and particular OS family.
            Exact configuration for what versions the upgrade is necessary, can be seen in
            {SOFTWARE_UPGRADE_PATH}.
            Upgrade procedure is similar to 'kubemarine upgrade --tasks=kubernetes', but without the Kubernetes upgrade.
            """.rstrip()
        )


class BalancerUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, upgrade_config: dict, package_name: str) -> None:
        super().__init__(f"upgrade_{package_name}")
        self.upgrade_config = upgrade_config
        self.package_name = package_name

    @property
    def action(self) -> Action:
        return BalancerUpgradeAction(self.upgrade_config, self.package_name)

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Upgrade {self.package_name!r} on balancers:
            Roughly equivalent to 'kubemarine install --tasks=deploy.loadbalancer.{self.package_name}.install',
            as if it is run in a clean environment.
            """.rstrip()
        )


class PluginUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, plugin_name: str, k8s_versions: List[str]) -> None:
        super().__init__(f"upgrade_{re.sub(r'-', '_', plugin_name)}")
        self.plugin_name = plugin_name
        self.k8s_versions = k8s_versions

    @property
    def action(self) -> Action:
        return PluginUpgradeAction(self.plugin_name, self.k8s_versions)

    @property
    def description(self) -> str:
        versions_list = '\n'.join(f" - {ver}" for ver in self.k8s_versions)

        return dedent(
            f"""\
            Upgrade {self.plugin_name!r} for the following Kubernetes versions:
            {{versions_list}}
            Roughly equivalent to 'kubemarine install --tasks=deploy.plugins' with all plugins disabled except the {self.plugin_name!r}.
            """.rstrip()
        ).format(versions_list=versions_list)


def load_upgrade_config() -> dict:
    with utils.open_internal(SOFTWARE_UPGRADE_PATH) as stream:
        upgrade_config: dict = yaml.safe_load(stream)
        return upgrade_config


def resolve_upgrade_patches() -> List[_SoftwareUpgradePatch]:
    upgrade_config = load_upgrade_config()

    upgrade_patches: List[_SoftwareUpgradePatch] = []

    # The order of upgrade is determined by the implementation below

    for thirdparty_name in ['crictl']:
        k8s_versions = upgrade_config['thirdparties'][thirdparty_name]
        if k8s_versions:
            verify_allowed_kubernetes_versions(k8s_versions)
            upgrade_patches.append(ThirdpartyUpgradePatch(thirdparty_name, k8s_versions))

    k8s_versions = [version
                    for pkg in ('docker', 'containerd', 'containerdio')
                    for v_key in ('version_rhel', 'version_rhel8', 'version_rhel9', 'version_debian')
                    for version in upgrade_config['packages'][pkg].get(v_key, [])]
    if k8s_versions:
        verify_allowed_kubernetes_versions(k8s_versions)
        upgrade_patches.append(CriUpgradePatch(upgrade_config))

    for package_name in ['haproxy', 'keepalived']:
        if any(upgrade_config['packages'][package_name].get(v_key)
               for v_key in ('version_rhel', 'version_rhel8', 'version_rhel9', 'version_debian')):
            upgrade_patches.append(BalancerUpgradePatch(upgrade_config, package_name))

    default_plugins = static.DEFAULTS['plugins']
    plugins = list(default_plugins)
    plugins.sort(key=get_default_plugin_priority)
    for plugin_name in plugins:
        k8s_versions = upgrade_config['plugins'][plugin_name]
        if k8s_versions:
            verify_allowed_kubernetes_versions(k8s_versions)
            upgrade_patches.append(PluginUpgradePatch(plugin_name, k8s_versions))

    return upgrade_patches


def get_default_plugin_priority(plugin: str) -> int:
    priority: int = static.DEFAULTS['plugins'][plugin]['installation']['priority']
    return priority


def verify_allowed_kubernetes_versions(kubernetes_versions: List[str]) -> None:
    not_allowed_versions = set(kubernetes_versions) - set(static.KUBERNETES_VERSIONS['compatibility_map'])
    if not_allowed_versions:
        raise Exception(f"Kubernetes versions {', '.join(map(repr, not_allowed_versions))} are not allowed.")


def load_patches() -> List[Patch]:
    patches = list(kubemarine.patches.patches)
    patches.extend(resolve_upgrade_patches())
    patches.sort(key=lambda p: p.priority())
    return patches


def new_parser() -> argparse.ArgumentParser:
    cli_help = '''
    Script for automated update of the environment for the current version of Kubemarine.

    How to use:

    '''

    parser = flow.new_common_parser(cli_help)
    parser.add_argument('--force-skip', dest='skip', metavar='SKIP',
                        default='',
                        help='define comma-separated patches to skip')

    parser.add_argument('--force-apply', dest='apply', metavar='APPLY',
                        default='',
                        help='define explicit comma-separated set of patches to apply')

    parser.add_argument('--list',
                        action='store_true',
                        help='list all patches')

    parser.add_argument('--describe', metavar='PATCH',
                        help='describe the specified patch')

    parser.add_argument('procedure_config', metavar='procedure_config',
                        type=str, help='config file for the procedure', nargs='?')

    return parser


def run(context: dict) -> None:
    args = context['execution_arguments']

    patches = load_patches()
    patch_ids = [patch.identifier for patch in patches]

    if args['list']:
        if patch_ids:
            print("Available patches list:")
            for patch_id in patch_ids:
                print(patch_id)
        else:
            print("No patches available.")
        exit(0)

    if args['describe']:
        for patch in patches:
            if patch.identifier == args['describe']:
                print(patch.description)
                exit(0)
        print(f"Unknown patch '{args['describe']}'")
        exit(1)

    skip = [] if not args['skip'] else args['skip'].split(",")
    apply = [] if not args['apply'] else args['apply'].split(",")

    if apply and (set(apply) - set(patch_ids)):
        print(f"Unknown patches {list(set(apply) - set(patch_ids))}")
        exit(1)

    if skip and (set(skip) - set(patch_ids)):
        print(f"Unknown patches {list(set(skip) - set(patch_ids))}")
        exit(1)

    if apply:
        positions = [patch_ids.index(apply_id) for apply_id in apply]
        if not all(positions[i] < positions[i + 1] for i in range(len(positions) - 1)):
            print("Incorrect order of patches to apply. See --list for correct order of patches.")
            exit(1)

    actions = []
    for patch in patches:
        if apply:
            if patch.identifier in apply:
                actions.append(patch.action)
        elif skip:
            if patch.identifier not in skip:
                actions.append(patch.action)
        else:
            actions.append(patch.action)

    if not actions:
        print("No patches to apply")
        exit(0)

    flow.ActionsFlow(actions).run_flow(context)


def create_context(cli_arguments: List[str] = None) -> dict:
    parser = new_parser()
    context = flow.create_context(parser, cli_arguments, procedure="migrate_kubemarine")
    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    run(context)


if __name__ == '__main__':
    main()
