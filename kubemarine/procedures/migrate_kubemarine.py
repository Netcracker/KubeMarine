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
import re
from abc import ABC, abstractmethod
from textwrap import dedent
from typing import List

import yaml

import kubemarine.patches
from kubemarine import kubernetes, plugins
from kubemarine.core import flow, static, utils
from kubemarine.core.action import Action
from kubemarine.core.patch import Patch, _SoftwareUpgradePatch
from kubemarine.core.resources import DynamicResources

SOFTWARE_UPGRADE_PATH = utils.get_internal_resource_path("patches/software_upgrade.yaml")


class SoftwareUpgradeAction(Action, ABC):
    def __init__(self, software_name: str, k8s_versions: List[str]):
        super().__init__(f'Upgrade {software_name}')
        self.software_name = software_name
        self.k8s_versions = k8s_versions

    def run(self, res: DynamicResources):
        # We should not call DynamicResources.cluster() and should only access the raw inventory,
        # because otherwise enrichment will start with probably not relevant validation.
        version = kubernetes.get_initial_kubernetes_version(res.raw_inventory())
        if version not in self.k8s_versions:
            res.logger().info(f"Patch is not relevant for kubernetes {version}")
            return

        self.specific_run(res)
        res.make_final_inventory()

    @abstractmethod
    def specific_run(self, res: DynamicResources):
        pass


class ThirdpartyUpgradeAction(SoftwareUpgradeAction):
    def specific_run(self, res: DynamicResources):
        # TODO implement
        pass


class CriUpgradeAction(Action):
    def __init__(self, upgrade_config: dict):
        super().__init__(f'Upgrade CRI')
        self.upgrade_config = upgrade_config

    def run(self, res: DynamicResources):
        # TODO implement
        res.make_final_inventory()


class BalancerUpgradeAction(Action):
    def __init__(self, software_name: str):
        super().__init__(f'Upgrade {software_name}')
        self.software_name = software_name

    def run(self, res: DynamicResources):
        # TODO implement
        res.make_final_inventory()


class PluginUpgradeAction(SoftwareUpgradeAction):
    def specific_run(self, res: DynamicResources):
        self.recreate_inventory = True

        cluster = res.cluster()
        upgrade_candidates = {
            self.software_name: cluster.inventory['plugins'][self.software_name]
        }
        # TODO despite that we are sure that the recommended version has changed,
        #  upgrade might still be not required if the effective configuration did not change.
        plugins.install(cluster, upgrade_candidates)

    def prepare_context(self, context: dict) -> None:
        context['upgrading_plugin'] = self.software_name

    def reset_context(self, context: dict) -> None:
        del context['upgrading_plugin']


class ThirdpartyUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, thirdparty_name: str, k8s_versions: List[str]):
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
    def __init__(self, upgrade_config: dict):
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
    def __init__(self, software_name: str):
        super().__init__(f"upgrade_{software_name}")
        self.software_name = software_name

    @property
    def action(self) -> Action:
        return BalancerUpgradeAction(self.software_name)

    @property
    def description(self) -> str:
        return dedent(
            f"""\
            Upgrade {self.software_name!r} on balancers:
            Roughly equivalent to 'kubemarine install --tasks=deploy.loadbalancer.{self.software_name}'.
            """.rstrip()
        )


class PluginUpgradePatch(_SoftwareUpgradePatch):
    def __init__(self, plugin_name: str, k8s_versions: List[str]):
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
        return yaml.safe_load(stream)


def resolve_upgrade_patches() -> List[_SoftwareUpgradePatch]:
    upgrade_config = load_upgrade_config()

    upgrade_patches: List[_SoftwareUpgradePatch] = []

    # The order of upgrade is determined by the implementation below

    for thirdparty_name in ['crictl']:
        k8s_versions = upgrade_config['thirdparties'][thirdparty_name]
        if k8s_versions:
            upgrade_patches.append(ThirdpartyUpgradePatch(thirdparty_name, k8s_versions))

    if any(upgrade_config['packages'][pkg].get(v_key)
           for pkg in ('docker', 'containerd', 'containerdio', 'podman')
           for v_key in ('version_rhel', 'version_rhel8', 'version_debian')):
        upgrade_patches.append(CriUpgradePatch(upgrade_config))

    for software_name in ['haproxy', 'keepalived']:
        if any(upgrade_config['packages'][software_name].get(v_key)
               for v_key in ('version_rhel', 'version_rhel8', 'version_debian')):
            upgrade_patches.append(BalancerUpgradePatch(software_name))

    default_plugins = static.DEFAULTS['plugins']
    plugins = list(default_plugins)
    plugins.sort(key=lambda p: default_plugins[p]['installation']['priority'])
    for plugin_name in plugins:
        k8s_versions = upgrade_config['plugins'][plugin_name]
        if k8s_versions:
            upgrade_patches.append(PluginUpgradePatch(plugin_name, k8s_versions))

    return upgrade_patches


def load_patches() -> List[Patch]:
    patches = list(kubemarine.patches.patches)
    patches.extend(resolve_upgrade_patches())
    patches.sort(key=lambda p: p.priority())
    return patches


def new_parser():
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


def run(context: dict):
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


def main(cli_arguments=None):
    parser = new_parser()
    context = flow.create_context(parser, cli_arguments, procedure="migrate_kubemarine")
    run(context)


if __name__ == '__main__':
    main()
