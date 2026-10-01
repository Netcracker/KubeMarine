# Copyright 2026 NetCracker Technology Corporation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import re

import jinja2
import yaml

from kubemarine.core import utils
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.patch import RegularPatch
from kubemarine.core.resources import DynamicResources
from kubemarine.kubernetes.object import KubernetesObject


def convert_kubeadm_config(config: dict) -> dict:
    """Read legacy configurations as v1beta4 without losing repeated arguments."""
    config = utils.deepcopy_yaml(config)
    if config.get('kind') not in ('ClusterConfiguration', 'InitConfiguration', 'JoinConfiguration'):
        return config
    if config.get('apiVersion', 'kubeadm.k8s.io/v1beta4') not in (
            'kubeadm.k8s.io/v1beta3', 'kubeadm.k8s.io/v1beta4'):
        raise ValueError(f"Unsupported kubeadm configuration API: {config['apiVersion']}")
    config['apiVersion'] = 'kubeadm.k8s.io/v1beta4'
    paths = [('apiServer', 'extraArgs'), ('scheduler', 'extraArgs'),
             ('controllerManager', 'extraArgs'), ('etcd', 'local', 'extraArgs'),
             ('nodeRegistration', 'kubeletExtraArgs')]
    for path in paths:
        parent = config
        for key in path[:-1]:
            parent = parent.get(key, {})
        key = path[-1]
        value = parent.get(key)
        if isinstance(value, dict):
            parent[key] = [{'name': name, 'value': arg} for name, arg in value.items()]
    if config['kind'] == 'ClusterConfiguration':
        config.get('apiServer', {}).pop('timeoutForControlPlane', None)
    elif config['kind'] == 'JoinConfiguration':
        timeout = config.get('discovery', {}).pop('timeout', None)
        if timeout is not None:
            config.setdefault('timeouts', {}).setdefault('discovery', timeout)
    return config


def migrate_inventory(inventory: dict) -> bool:
    """Migrate explicit inventory overrides without expanding defaults."""
    services: dict = inventory.get('services', {})
    original_config = services.get('kubeadm')
    if original_config is None:
        return False
    config = utils.deepcopy_yaml(original_config)
    timeout = config.get('apiServer', {}).get('timeoutForControlPlane')
    if timeout is not None:
        timeouts = services.get('kubeadm_timeouts', {})
        current = timeouts.get('controlPlaneComponentHealthCheck', timeout)
        if current != timeout:
            raise ValueError('Conflicting kubeadm controlPlaneComponentHealthCheck and timeoutForControlPlane')
    # A partial override does not necessarily contain kind or apiVersion.
    kind = config.get('kind')
    api_version = config.get('apiVersion')
    config['kind'] = 'ClusterConfiguration'
    converted = convert_kubeadm_config(config)
    if kind is None:
        converted.pop('kind')
    if api_version is None:
        converted.pop('apiVersion')
    changed = converted != original_config
    if changed:
        original_config.clear()
        original_config.update(converted)
    if timeout is not None:
        services.setdefault('kubeadm_timeouts', {})['controlPlaneComponentHealthCheck'] = timeout
    return bool(changed)


def migrate_kubeadm_cluster_config(config: dict, control_plane: NodeGroup) -> dict:
    """Use installed kubeadm to migrate a stored ClusterConfiguration to v1beta4."""
    if config.get('kind') != 'ClusterConfiguration':
        raise ValueError('kubeadm-config does not contain a ClusterConfiguration')
    api_version = config.get('apiVersion')
    if api_version == 'kubeadm.k8s.io/v1beta4':
        return utils.deepcopy_yaml(config)
    if api_version != 'kubeadm.k8s.io/v1beta3':
        raise ValueError(f'Unsupported kubeadm configuration API: {api_version}')

    path = utils.get_remote_tmp_path('kubeadm-config-migration.yaml')
    try:
        control_plane.put(io.StringIO(yaml.safe_dump(config)), path, sudo=True)
        migrated = control_plane.sudo(f'kubeadm config migrate --old-config={path}').get_simple_out()

        cluster_configs = [document for document in yaml.safe_load_all(migrated)
                           if isinstance(document, dict) and document.get('kind') == 'ClusterConfiguration']
        if len(cluster_configs) != 1:
            raise ValueError('kubeadm config migrate must produce exactly one ClusterConfiguration')

        converted = cluster_configs[0]
        if converted.get('apiVersion') != 'kubeadm.k8s.io/v1beta4':
            raise ValueError('kubeadm config migrate did not produce a v1beta4 ClusterConfiguration')

        control_plane.put(io.StringIO(yaml.safe_dump(converted)), path, sudo=True)
        control_plane.sudo(f'kubeadm config validate --config={path}')
        return converted
    finally:
        control_plane.sudo(f'rm -f {path}', warn=True)


def migrate_kubeadm_configmap(cluster: KubernetesCluster) -> None:
    """Migrate the stored ClusterConfiguration with the installed kubeadm binary."""
    control_plane = cluster.nodes['control-plane'].get_first_member()
    configmap = KubernetesObject(cluster, 'ConfigMap', 'kubeadm-config', 'kube-system')
    configmap.reload(control_plane)
    original = configmap.obj['data']['ClusterConfiguration']
    config = yaml.safe_load(original)
    converted = migrate_kubeadm_cluster_config(config, control_plane)
    if converted == config:
        cluster.log.info('kubeadm-config already uses v1beta4')
        return

    utils.dump_file(cluster, configmap.to_yaml(), 'kubeadm-config-before-v1beta4.yaml')
    configmap.obj['data']['ClusterConfiguration'] = yaml.safe_dump(converted)
    configmap.apply(control_plane)


def _access(name: str) -> str:
    return rf'''(?:\s*\.\s*(?:{name})|\s*\[\s*['"](?:{name})['"]\s*\])'''


_ARG_REFERENCE = re.compile(
    r'services' + _access('kubeadm')
    + '(?:' + _access('apiServer|scheduler|controllerManager')
    + '|' + _access('etcd') + _access('local') + ')'
    + _access('extraArgs')
    + r'''\s*\[\s*(['"])([\w-]+)\1\s*\]''')


def migrate_templates(value: object) -> bool:
    """Rewrite direct named-argument lookups, preserving templates as templates."""
    changed = False
    if not isinstance(value, (dict, list)):
        return False
    for key, item in (value.items() if isinstance(value, dict) else enumerate(value)):
        if isinstance(item, str) and ('{{' in item or '{%' in item):
            # The lexer distinguishes actual variable references from quoted
            # strings, comments and raw text containing similar expressions.
            tokens = list(jinja2.Environment().lex(item))
            source = ''.join(token[2] for token in tokens)
            offset = 0
            replacements = []
            previous = ''
            for _, token_type, text in tokens:
                if token_type == 'name' and text == 'services' and previous != '.':
                    match = _ARG_REFERENCE.match(source, offset)
                    if match:
                        expression = match.group(0)
                        args = expression[:expression.rfind('[')].rstrip()
                        replacement = (f'({args} | selectattr("name", "equalto", "{match.group(2)}") '
                                       '| map(attribute="value") | list | last)')
                        replacements.append((offset, match.end(), replacement))
                offset += len(text)
                if token_type != 'whitespace':
                    previous = text
            if replacements:
                for start, end, replacement in reversed(replacements):
                    source = source[:start] + replacement + source[end:]
                value[key] = source
                changed = True
        else:
            changed = migrate_templates(item) or changed
    return changed


class MigrationAction(Action):
    def __init__(self) -> None:
        super().__init__('Migrate kubeadm configuration to v1beta4')

    def run(self, res: DynamicResources) -> None:
        # Work on a copy: an invalid template or failed ConfigMap migration
        # must not leave partially converted user inventory in memory.
        original = utils.deepcopy_yaml(res.inventory())
        converted = utils.deepcopy_yaml(original)
        inventory_changed = migrate_inventory(converted)
        inventory_changed = migrate_templates(converted) or inventory_changed
        res.inventory().clear()
        res.inventory().update(converted)
        try:
            migrate_kubeadm_configmap(res.cluster())
        except BaseException:
            res.inventory().clear()
            res.inventory().update(original)
            raise

        # Persist the inventory only after the in-cluster migration succeeds.
        self.recreate_inventory = inventory_changed


class KubeadmV1Beta4Patch(RegularPatch):
    def __init__(self) -> None:
        super().__init__('migrate_kubeadm_v1beta4')

    @property
    def action(self) -> Action:
        return MigrationAction()

    @property
    def description(self) -> str:
        return ('After updating KubeMarine, convert the inventory and kube-system/kubeadm-config to v1beta4 '
                'before running checks or maintenance procedures. This patch runs before other migration patches. '
                'Inventory extraArgs are converted to named-argument lists and timeoutForControlPlane is moved '
                'to services.kubeadm_timeouts. The ConfigMap is migrated and validated using the installed '
                'kubeadm while preserving the running Kubernetes version and custom settings. The migration '
                'procedure backs up a changed inventory, and the original ConfigMap is saved in the dump '
                'directory before it is updated. No components are restarted.')
