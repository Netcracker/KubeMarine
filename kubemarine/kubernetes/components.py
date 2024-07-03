# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import re
from textwrap import dedent
from typing import List, Optional, Dict, Callable, Sequence, Union

import yaml
from jinja2 import Template
from ordered_set import OrderedSet

from kubemarine import plugins, system
from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, DeferredGroup, CollectorCallback, AbstractGroup, RunResult
from kubemarine.core.yaml_merger import override_merger
from kubemarine.kubernetes.object import KubernetesObject

ERROR_WAIT_FOR_PODS_NOT_SUPPORTED = "Waiting for pods of {components} components is currently not supported"
ERROR_RESTART_NOT_SUPPORTED = "Restart of {components} components is currently not supported"
ERROR_RECONFIGURE_NOT_SUPPORTED = "Reconfiguration of {components} components is currently not supported"

COMPONENTS_CONSTANTS: dict = {
    'kube-apiserver/cert-sans': {
        'sections': [
            ['services', 'kubeadm', 'apiServer', 'certSANs'],
        ],
        'init_phase': 'certs apiserver',
    },
    'kube-apiserver': {
        'sections': [
            ['services', 'kubeadm', 'apiServer'],
            ['services', 'kubeadm_patches', 'apiServer'],
        ],
        'patch': {
            'section': 'apiServer',
            'target_template': r'kube-apiserver\*',
            'file': 'kube-apiserver+json.json'
        },
        'init_phase': 'control-plane apiserver',
    },
    'kube-scheduler': {
        'sections': [
            ['services', 'kubeadm', 'scheduler'],
            ['services', 'kubeadm_patches', 'scheduler'],
        ],
        'patch': {
            'section': 'scheduler',
            'target_template': r'kube-scheduler\*',
            'file': 'kube-scheduler+json.json'
        },
        'init_phase': 'control-plane scheduler',
    },
    'kube-controller-manager': {
        'sections': [
            ['services', 'kubeadm', 'controllerManager'],
            ['services', 'kubeadm_patches', 'controllerManager'],
        ],
        'patch': {
            'section': 'controllerManager',
            'target_template': r'kube-controller-manager\*',
            'file': 'kube-controller-manager+json.json'
        },
        'init_phase': 'control-plane controller-manager',
    },
    'etcd': {
        'sections': [
            ['services', 'kubeadm', 'etcd'],
            ['services', 'kubeadm_patches', 'etcd'],
        ],
        'patch': {
            'section': 'etcd',
            'target_template': r'etcd\*',
            'file': 'etcd+json.json'
        },
        'init_phase': 'etcd local',
    },
    'kubelet': {
        'sections': [
            ['services', 'kubeadm_kubelet'],
            ['services', 'kubeadm_patches', 'kubelet'],
        ],
        'patch': {
            'section': 'kubelet',
            'target_template': r'kubeletconfiguration\*',
            'file': 'kubeletconfiguration.yaml'
        }
    },
    'kube-proxy': {
        'sections': [
            ['services', 'kubeadm_kube-proxy'],
        ]
    },
}

CONFIGMAPS_CONSTANTS = {
    'kubeadm-config': {
        'section': 'kubeadm',
        'key': 'ClusterConfiguration',
        'init_phase': 'upload-config kubeadm',
    },
    'kubelet-config': {
        'section': 'kubeadm_kubelet',
        'key': 'kubelet',
        'init_phase': 'upload-config kubelet',
    },
    'kube-proxy': {
        'section': 'kubeadm_kube-proxy',
        'key': 'config.conf',
    },
}


CONTROL_PLANE_COMPONENTS = ["kube-apiserver", "kube-scheduler", "kube-controller-manager", "etcd"]
CONTROL_PLANE_SPECIFIC_COMPONENTS = ['kube-apiserver/cert-sans'] + CONTROL_PLANE_COMPONENTS
NODE_COMPONENTS = ["kubelet", "kube-proxy"]
ALL_COMPONENTS = CONTROL_PLANE_SPECIFIC_COMPONENTS + NODE_COMPONENTS
COMPONENTS_SUPPORT_PATCHES = CONTROL_PLANE_COMPONENTS + ['kubelet']


class KubeadmConfig:
    def __init__(self, cluster: KubernetesCluster):
        self.cluster = cluster

        inventory = cluster.inventory
        self.maps: Dict[str, dict] = {
            configmap: inventory["services"][constants['section']]
            for configmap, constants in CONFIGMAPS_CONSTANTS.items()}

        self.loaded_maps: Dict[str, KubernetesObject] = {}

    def is_loaded(self, configmap: str) -> bool:
        return configmap in self.loaded_maps

    def load(self, configmap: str, control_plane: NodeGroup, edit_func: Callable[[dict], dict] = None) -> dict:
        """
        Load ConfigMap as object, retrieve plain config from it, and apply `edit_func` to the plain config if provided.

        :param configmap: name of ConfigMap
        :param edit_func: function to apply changes
        :param control_plane: Use this control plane node to fetch the ConfigMap.
        """
        configmap_obj = KubernetesObject(self.cluster, 'ConfigMap', configmap, 'kube-system')
        configmap_obj.reload(control_plane)

        self.loaded_maps[configmap] = configmap_obj

        key = CONFIGMAPS_CONSTANTS[configmap]['key']
        config: dict = yaml.safe_load(configmap_obj.obj["data"][key])

        if edit_func is not None:
            config = edit_func(config)
            configmap_obj.obj["data"][key] = yaml.dump(config)

        self.maps[configmap] = config
        return config

    def apply(self, configmap: str, control_plane: NodeGroup) -> None:
        """
        Apply ConfigMap that was previously changed using edit().

        :param configmap: name of ConfigMap
        :param control_plane: Use this control plane node to apply the ConfigMap.
        :return:
        """
        if not self.is_loaded(configmap):
            raise ValueError(f"To apply changed {configmap} ConfigMap, it is necessary to fetch it first")

        self.loaded_maps[configmap].apply(control_plane)

    def to_yaml(self, init_config: dict) -> str:
        configs = list(self.maps.values())
        configs.append(init_config)
        return yaml.dump_all(configs)

    def merge_with_inventory(self, configmap: str) -> Callable[[dict], dict]:
        def merge_func(config_: dict) -> dict:
            patch_config: dict = KubeadmConfig(self.cluster).maps[configmap]
            # It seems that all default lists are always overridden with custom instead of appending,
            # and so override merger seems the most suitable.
            config_ = override_merger.merge(config_, utils.deepcopy_yaml(patch_config))
            return config_

        return merge_func


def kubeadm_extended_dryrun(cluster: KubernetesCluster) -> bool:
    return kubernetes_minor_release_at_least(cluster.inventory, "v1.26")


def is_container_runtime_not_configurable(cluster: KubernetesCluster) -> bool:
    return kubernetes_minor_release_at_least(cluster.inventory, "v1.27")


def kube_proxy_overwrites_higher_system_values(cluster: KubernetesCluster) -> bool:
    return kubernetes_minor_release_at_least(cluster.inventory, "v1.29")


def kubernetes_minor_release_at_least(inventory: dict, minor_version: str) -> bool:
    kubernetes_version = inventory["services"]["kubeadm"]["kubernetesVersion"]
    return utils.version_key(kubernetes_version)[0:2] >= utils.minor_version_key(minor_version)


def get_init_config(cluster: KubernetesCluster, group: AbstractGroup[RunResult], *,
                    init: bool, join_dict: dict = None) -> dict:
    inventory = cluster.inventory

    if join_dict is None:
        join_dict = {}

    init_kind = 'InitConfiguration' if init else 'JoinConfiguration'

    control_plane_spec = {}
    if group.nodes_amount() > 1:
        control_planes = group.new_group(lambda node: 'control-plane' in node['roles'])
        if not control_planes.is_empty():
            raise Exception("Init/Join configuration for control planes should be unique")

        control_plane = False
        worker = True
    else:
        node_config = group.get_config()
        control_plane = 'control-plane' in node_config['roles']
        worker = 'worker' in node_config['roles']
        if control_plane:
            control_plane_spec = {'localAPIEndpoint': {
                'advertiseAddress': node_config['internal_address']
            }}

    init_config: dict = {
        'apiVersion': inventory["services"]["kubeadm"]['apiVersion'],
        'kind': init_kind,
        'patches': {'directory': '/etc/kubernetes/patches'},
    }
    if init:
        if control_plane:
            init_config.update(control_plane_spec)
    else:
        if control_plane:
            control_plane_spec['certificateKey'] = join_dict['certificate-key']
            init_config['controlPlane'] = control_plane_spec

        init_config['discovery'] = {
            'bootstrapToken': {
                'apiServerEndpoint': inventory["services"]["kubeadm"]['controlPlaneEndpoint'],
                'token': join_dict['token'],
                'caCertHashes': [
                    join_dict['discovery-token-ca-cert-hash']
                ]
            }
        }

    if control_plane and worker:
        init_config.setdefault('nodeRegistration', {})['taints'] = []

    _configure_container_runtime(cluster, init_config)

    return init_config


def get_kubeadm_config(cluster: KubernetesCluster, init_config: dict) -> str:
    return KubeadmConfig(cluster).to_yaml(init_config)


def _configure_container_runtime(cluster: KubernetesCluster, kubeadm_config: dict) -> None:
    kubelet_extra_args = kubeadm_config.setdefault('nodeRegistration', {}).setdefault('kubeletExtraArgs', {})

    kubeadm_config['nodeRegistration']['criSocket'] = '/var/run/containerd/containerd.sock'

    if not is_container_runtime_not_configurable(cluster):
        kubelet_extra_args['container-runtime'] = 'remote'

    kubelet_extra_args['container-runtime-endpoint'] = 'unix:///run/containerd/containerd.sock'


def reconfigure_components(group: NodeGroup, components: List[str],
                           *,
                           edit_functions: Dict[str, Callable[[dict], dict]] = None,
                           force_restart: bool = False) -> None:
    """
    Reconfigure the specified `components` on `group` of nodes.
    Control-plane nodes are reconfigured first.
    The cluster is not required to be working to update control plane manifests.

    :param group: nodes to reconfigure components on
    :param components: List of control plane components or `kube-proxy`, or `kubelet` to reconfigure.
    :param edit_functions: Callables that edit the specified kubeadm-managed ConfigMaps in a custom way.
                           The ConfigMaps are fetched from the first control plane,
                           instead of being generated.
                           This implies necessity of working API server.
    :param force_restart: Restart the given `components` even if nothing has changed in their configuration.
    """
    not_supported = list(OrderedSet[str](components) - set(ALL_COMPONENTS))
    if not_supported:
        raise Exception(ERROR_RECONFIGURE_NOT_SUPPORTED.format(components=not_supported))

    if edit_functions is None:
        edit_functions = {}

    cluster: KubernetesCluster = group.cluster
    logger = cluster.log

    control_planes = (cluster.nodes['control-plane']
                      .intersection_group(group))
    workers = (cluster.make_group_from_roles(['worker'])
               .exclude_group(control_planes)
               .intersection_group(group))

    group = control_planes.include_group(workers)
    if group.is_empty():
        logger.debug("No Kubernetes nodes to reconfigure components")
        return

    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    if not control_planes.is_empty():
        first_control_plane = control_planes.get_first_member()

    timestamp = utils.get_current_timestamp_formatted()
    backup_dir = '/etc/kubernetes/tmp/kubemarine-backup-' + timestamp
    logger.debug(f"Using backup directory {backup_dir}")

    kubeadm_config = KubeadmConfig(cluster)
    for configmap, func in edit_functions.items():
        kubeadm_config.load(configmap, first_control_plane, func)

    # This configuration will be used for `kubeadm init phase upload-config` phase.
    # InitConfiguration is necessary to specify patches directory.
    # Use patches from the first control plane, to make it the same as during regular installation.
    # Patches are used to upload KubeletConfiguration for some reason (which is likely a gap)
    # https://github.com/kubernetes/kubernetes/issues/123090
    upload_config = '/etc/kubernetes/upload-config.yaml'
    upload_config_uploaded = False

    def prepare_upload_config() -> None:
        nonlocal upload_config_uploaded
        if upload_config_uploaded:
            return

        logger.debug(f"Uploading cluster config to control plane: {first_control_plane.get_node_name()}")
        _upload_config(cluster, first_control_plane, kubeadm_config, upload_config)

        upload_config_uploaded = True

    # This configuration will be generated for control plane nodes,
    # and will be used to `kubeadm init phase control-plane / etcd / certs`.
    reconfigure_config = '/etc/kubernetes/reconfigure-config.yaml'

    _prepare_nodes_to_reconfigure_components(cluster, group, components,
                                             kubeadm_config, reconfigure_config, backup_dir)

    kubeadm_config_updated = False
    kubelet_config_updated = False
    kube_proxy_config_updated = False
    kube_proxy_changed = False
    for node in (control_planes.get_ordered_members_list() + workers.get_ordered_members_list()):
        _components = _choose_components(node, components)
        if not _components:
            continue

        # Firstly reconfigure components that do not require working API server
        control_plane_components = list(OrderedSet[str](_components) & set(CONTROL_PLANE_SPECIFIC_COMPONENTS))
        if control_plane_components:
            _reconfigure_control_plane_components(cluster, node, control_plane_components, force_restart,
                                                  reconfigure_config, backup_dir)

            # Upload kubeadm-config after control plane components are successfully reconfigured on the first node.
            if not kubeadm_config_updated:
                prepare_upload_config()
                _update_configmap(cluster, first_control_plane, 'kubeadm-config',
                                  _configmap_init_phase_uploader('kubeadm-config', upload_config),
                                  backup_dir)
                kubeadm_config_updated = True

        node_components = list(OrderedSet[str](_components) & set(NODE_COMPONENTS))
        if node_components:
            if 'kubelet' in node_components and not kubelet_config_updated:
                prepare_upload_config()
                _update_configmap(cluster, first_control_plane, 'kubelet-config',
                                  _configmap_init_phase_uploader('kubelet-config', upload_config),
                                  backup_dir)

                kubelet_config_updated = True

            if 'kube-proxy' in node_components and not kube_proxy_config_updated:
                kube_proxy_changed = _update_configmap(cluster, first_control_plane, 'kube-proxy',
                                                       _kube_proxy_configmap_uploader(cluster, kubeadm_config),
                                                       backup_dir)

                kube_proxy_config_updated = True

            _reconfigure_node_components(cluster, node, node_components, force_restart, first_control_plane,
                                         kube_proxy_changed, backup_dir)


def restart_components(group: NodeGroup, components: List[str]) -> None:
    """
    Currently it is supported to restart only
    'kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd'.

    :param group: nodes to restart components on
    :param components: Kubernetes components to restart
    """
    not_supported = list(OrderedSet[str](components) - set(CONTROL_PLANE_COMPONENTS))
    if not_supported:
        raise Exception(ERROR_RESTART_NOT_SUPPORTED.format(components=not_supported))

    cluster: KubernetesCluster = group.cluster

    for node in group.get_ordered_members_list():
        _components = _choose_components(node, components)
        _restart_containers(cluster, node, _components)
        wait_for_pods(node, _components)


def wait_for_pods(group: NodeGroup, components: Sequence[str] = None) -> None:
    """
    Wait for pods of Kubernetes components on the given `group` of nodes.
    All relevant components are waited for unless specific list of `components` is given.
    For nodes that are not control planes, only 'kube-proxy' can be waited for.

    :param group: nodes to wait pods on
    :param components: Kubernetes components to wait for.
    """
    if components is not None:
        if not components:
            return

        not_supported = list(OrderedSet[str](components) - set(CONTROL_PLANE_COMPONENTS) - {'kube-proxy'})
        if not_supported:
            raise Exception(ERROR_WAIT_FOR_PODS_NOT_SUPPORTED.format(components=not_supported))

    cluster: KubernetesCluster = group.cluster
    first_control_plane = cluster.nodes['control-plane'].get_first_member()
    expect_config = cluster.inventory['globals']['expect']['pods']['kubernetes']

    for node in group.get_ordered_members_list():
        node_name = node.get_node_name()
        is_control_plane = 'control-plane' in node.get_config()['roles']
        cluster.log.debug(f"Waiting for system pods on node: {node_name}")

        if components is not None:
            _components = list(components)
        else:
            _components = ['kube-proxy']
            if is_control_plane:
                _components.extend(CONTROL_PLANE_COMPONENTS)

        _components = _choose_components(node, _components)
        if not _components:
            continue

        control_plane = node
        if not is_control_plane:
            control_plane = first_control_plane

        plugins.expect_pods(cluster, _components, namespace='kube-system',
                            control_plane=control_plane, node_name=node_name,
                            timeout=expect_config['timeout'],
                            retries=expect_config['retries'])


# function to create kubeadm patches and put them to a node
def create_kubeadm_patches_for_node(cluster: KubernetesCluster, node: NodeGroup) -> None:
    cluster.log.verbose(f"Create and upload kubeadm patches to %s..." % node.get_node_name())
    node.sudo("mkdir -p /etc/kubernetes/patches")
    defer = node.new_defer()
    for component in COMPONENTS_SUPPORT_PATCHES:
        _create_kubeadm_patches_for_component_on_node(cluster, defer, component)

    defer.flush()


def patch_kubelet_configmap(control_plane: AbstractGroup[RunResult]) -> None:
    """
    Apply W/A until https://github.com/kubernetes/kubeadm/issues/3034 is resolved
    for all the supported Kubernetes versions.

    :param control_plane: control plane to operate on
    """
    # Make sure to check kubeadm_kubelet in the inventory.
    cluster: KubernetesCluster = control_plane.cluster
    kubeadm_config = KubeadmConfig(cluster)
    if 'resolvConf' in kubeadm_config.maps['kubelet-config']:
        return

    control_plane.sudo(
        f'kubectl get cm -n kube-system kubelet-config -o yaml '
        '| grep -v "resolvConf:" '
        '| sudo kubectl apply -f -')


def _upload_config(cluster: KubernetesCluster, control_plane: AbstractGroup[RunResult],
                   kubeadm_config: KubeadmConfig, remote_path: str,
                   *, patches_dir: str = '/etc/kubernetes/patches') -> None:
    name = remote_path.rstrip('.yaml').split('/')[-1]

    init_config = get_init_config(cluster, control_plane, init=True)
    init_config['patches']['directory'] = patches_dir
    config = kubeadm_config.to_yaml(init_config)
    utils.dump_file(cluster, config, f"{name}_{control_plane.get_node_name()}.yaml")

    control_plane.put(io.StringIO(config), remote_path, sudo=True)


def _update_configmap(cluster: KubernetesCluster, control_plane: NodeGroup, configmap: str,
                      uploader: Callable[[DeferredGroup], None], backup_dir: str) -> bool:
    logger = cluster.log

    logger.debug(f"Updating {configmap} ConfigMap")
    defer = control_plane.new_defer()
    collector = CollectorCallback(cluster)

    key = CONFIGMAPS_CONSTANTS[configmap]['key'].replace('.', r'\.')
    configmap_cmd = f'sudo kubectl get cm -n kube-system {configmap} -o=jsonpath="{{.data.{key}}}"'

    # backup
    defer.run(f'sudo mkdir -p {backup_dir}')
    backup_file = f'{backup_dir}/{configmap}.yaml'
    defer.run(f'(set -o pipefail && {configmap_cmd} | sudo tee {backup_file}) > /dev/null')

    # update
    uploader(defer)

    # compare
    defer.run(f'sudo cat {backup_file}', callback=collector)
    defer.run(configmap_cmd, callback=collector)

    defer.flush()

    results = collector.results[defer.get_host()]
    return _detect_changes(logger, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=f'{configmap} ConfigMap')


def _configmap_init_phase_uploader(configmap: str, upload_config: str) -> Callable[[DeferredGroup], None]:
    def upload(control_plane: DeferredGroup) -> None:
        init_phase = CONFIGMAPS_CONSTANTS[configmap]['init_phase']
        control_plane.run(f'sudo kubeadm init phase {init_phase} --config {upload_config}')
        if configmap == 'kubelet-config':
            patch_kubelet_configmap(control_plane)

    return upload


def _kube_proxy_configmap_uploader(cluster: KubernetesCluster, kubeadm_config: KubeadmConfig) \
        -> Callable[[DeferredGroup], None]:

    # Unfortunately, there is no suitable kubeadm command to upload the generated ConfigMap.
    # This makes it impossible to reset some property to default by deleting it from `services.kubeadm_kube-proxy`.

    def upload(control_plane_deferred: DeferredGroup) -> None:
        control_plane_deferred.flush()
        control_plane = cluster.make_group(control_plane_deferred.get_hosts())

        # reconfigure_components() can be called with custom editing function.
        # The ConfigMap is already fetched and changed.
        if not kubeadm_config.is_loaded('kube-proxy'):
            kubeadm_config.load('kube-proxy', control_plane, kubeadm_config.merge_with_inventory('kube-proxy'))

        # Apply updated kube-proxy ConfigMap
        kubeadm_config.apply('kube-proxy', control_plane)

    return upload


def _choose_components(node: AbstractGroup[RunResult], components: List[str]) -> List[str]:
    roles = node.get_config()['roles']

    return [c for c in components if c in NODE_COMPONENTS and set(roles) & {'control-plane', 'worker'}
            or 'control-plane' in roles and c in CONTROL_PLANE_SPECIFIC_COMPONENTS]


def _prepare_nodes_to_reconfigure_components(cluster: KubernetesCluster, group: NodeGroup, components: List[str],
                                             kubeadm_config: KubeadmConfig,
                                             reconfigure_config: str, backup_dir: str) -> None:
    logger = cluster.log
    defer = group.new_defer()
    for node in defer.get_ordered_members_list():
        _components = _choose_components(node, components)
        if not _components:
            continue

        if set(_components) & set(CONTROL_PLANE_SPECIFIC_COMPONENTS):
            logger.debug(f"Uploading config for control plane components on node: {node.get_node_name()}")
            _upload_config(cluster, node, kubeadm_config, reconfigure_config)

        if set(_components) & set(COMPONENTS_SUPPORT_PATCHES):
            node.sudo("mkdir -p /etc/kubernetes/patches")
            node.sudo(f'mkdir -p {backup_dir}/patches')

        if set(_components) & set(CONTROL_PLANE_COMPONENTS):
            node.sudo(f'mkdir -p {backup_dir}/manifests')

        for component in _components:
            if component not in COMPONENTS_SUPPORT_PATCHES:
                continue

            _create_kubeadm_patches_for_component_on_node(cluster, node, component, backup_dir)

    defer.flush()


def _reconfigure_control_plane_components(cluster: KubernetesCluster, node: NodeGroup, components: List[str],
                                          force_restart: bool,
                                          reconfigure_config: str, backup_dir: str) -> None:
    logger = cluster.log
    logger.debug(f"Reconfiguring control plane components {components} on node: {node.get_node_name()}")

    defer = node.new_defer()

    containers_restart = OrderedSet[str]()
    pods_wait = OrderedSet[str]()
    for component in components:
        if component == 'kube-apiserver/cert-sans':
            _reconfigure_apiserver_certsans(defer, reconfigure_config, backup_dir)
            containers_restart.add('kube-apiserver')
            pods_wait.add('kube-apiserver')
            continue

        # Let's anyway wait for pods as the component may be broken due to previous runs.
        pods_wait.add(component)
        if (_reconfigure_control_plane_component(cluster, defer, component, reconfigure_config, backup_dir)
                or force_restart):
            containers_restart.add(component)
        else:
            # Manifest file may be changed in formatting but not in meaningful content.
            # Kubelet is not observed to restart the container in this case, neither will we.
            pass

    defer.flush()
    _restart_containers(cluster, node, containers_restart)
    wait_for_pods(node, pods_wait)


def _reconfigure_apiserver_certsans(node: DeferredGroup, reconfigure_config: str, backup_dir: str) -> None:
    apiserver_certs = r'find /etc/kubernetes/pki/ -name apiserver.\*'

    # backup
    node.sudo(f'mkdir -p {backup_dir}/pki')
    node.sudo(f'{apiserver_certs} -exec cp {{}} {backup_dir}/pki \\;')

    # create cert
    node.sudo(f'{apiserver_certs} -delete')
    init_phase = COMPONENTS_CONSTANTS['kube-apiserver/cert-sans']['init_phase']
    node.sudo(f'kubeadm init phase {init_phase} --config {reconfigure_config}', pty=True)


def _reconfigure_control_plane_component(cluster: KubernetesCluster, node: DeferredGroup, component: str,
                                         reconfigure_config: str, backup_dir: str) -> bool:
    manifest = f'/etc/kubernetes/manifests/{component}.yaml'
    backup_file = f'{backup_dir}/manifests/{component}.yaml'
    collector = CollectorCallback(cluster)

    # backup
    node.sudo(f"cp {manifest} {backup_file}")

    # update
    init_phase = COMPONENTS_CONSTANTS[component]['init_phase']
    node.sudo(f'kubeadm init phase {init_phase} --config {reconfigure_config}', pty=True)

    # compare
    node.sudo(f'cat {backup_file}', callback=collector)
    node.sudo(f'cat {manifest}', callback=collector)

    node.flush()

    results = collector.results[node.get_host()]
    return _detect_changes(cluster.log, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=manifest)


def _reconfigure_node_components(cluster: KubernetesCluster, node: NodeGroup, components: List[str],
                                 force_restart: bool, control_plane: NodeGroup,
                                 kube_proxy_changed: bool, backup_dir: str) -> None:
    logger = cluster.log

    is_control_plane = 'control-plane' in node.get_config()['roles']
    kube_proxy_restart = kube_proxy_changed or force_restart
    containers_restart = OrderedSet[str]()
    pods_wait = OrderedSet[str]()
    if 'kube-proxy' in components:
        pods_wait.add('kube-proxy')

    if 'kubelet' in components:
        logger.debug(f"Reconfiguring kubelet on node: {node.get_node_name()}")

        pods_wait.add('kube-proxy')
        if is_control_plane:
            pods_wait.update(CONTROL_PLANE_COMPONENTS)

        defer = node.new_defer()
        if _reconfigure_kubelet(cluster, defer, backup_dir) or force_restart:
            system.restart_service(defer, 'kubelet')
            # It is not clear how to check that kubelet is healthy.
            # Let's restart and check health of all components.
            kube_proxy_restart = True
            if is_control_plane:
                # No need to manually kill container for kube-proxy. It is restarted as soon as pod is deleted.
                containers_restart.update(CONTROL_PLANE_COMPONENTS)

        defer.flush()

    # Delete pod for 'kube-proxy' early while 'kube-apiserver' is expected to be available.
    if kube_proxy_restart:
        _delete_pods(cluster, node, control_plane, ['kube-proxy'])

    _restart_containers(cluster, node, containers_restart)
    wait_for_pods(node, pods_wait)


def _reconfigure_kubelet(cluster: KubernetesCluster, node: DeferredGroup,
                         backup_dir: str) -> bool:
    config = '/var/lib/kubelet/config.yaml'
    backup_file = f'{backup_dir}/kubelet/config.yaml'
    collector = CollectorCallback(cluster)

    # backup
    node.sudo(f'mkdir -p {backup_dir}/kubelet')
    node.sudo(f"cp {config} {backup_file}")

    # update
    node.sudo(f'kubeadm upgrade node phase kubelet-config --patches=/etc/kubernetes/patches', pty=True)

    # compare
    node.sudo(f'cat {backup_file}', callback=collector)
    node.sudo(f'cat {config}', callback=collector)

    node.flush()

    results = collector.results[node.get_host()]
    return _detect_changes(cluster.log, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=config)


def compare_manifests(cluster: KubernetesCluster, *, with_inventory: bool) \
        -> Dict[str, Dict[str, Optional[str]]]:
    """
    Generate manifests in dry-run mode for all control plane components on all control plane nodes,
    and compare with already present manifests.

    :param cluster: KubernetesCluster instance
    :param with_inventory: flag if cluster configuration should be generated from the inventory
    :return: mapping host -> component -> diff string
    """
    kubeadm_config = KubeadmConfig(cluster)
    if not with_inventory:
        kubeadm_config.load('kubeadm-config', cluster.nodes['control-plane'].get_first_member())

    control_planes = cluster.nodes['control-plane'].new_defer()
    temp_config = utils.get_remote_tmp_path()
    patches_dir = '/etc/kubernetes/patches'
    if with_inventory:
        patches_dir = utils.get_remote_tmp_path()

    components = [c for c in CONTROL_PLANE_COMPONENTS
                  if c != 'etcd' or kubeadm_extended_dryrun(cluster)]

    tmp_dirs_cmd = "sh -c 'sudo ls /etc/kubernetes/tmp/ | grep dryrun 2>/dev/null || true'"
    old_tmp_dirs = CollectorCallback(cluster)
    new_tmp_dirs = CollectorCallback(cluster)
    for defer in control_planes.get_ordered_members_list():
        _upload_config(cluster, defer, kubeadm_config, temp_config, patches_dir=patches_dir)
        if with_inventory:
            defer.sudo(f'mkdir -p {patches_dir}')

        for component in components:
            if with_inventory:
                _create_kubeadm_patches_for_component_on_node(cluster, defer, component,
                                                              patches_dir=patches_dir, reset=False)

            defer.sudo(tmp_dirs_cmd, callback=old_tmp_dirs)

            init_phase = COMPONENTS_CONSTANTS[component]['init_phase']
            defer.sudo(f'kubeadm init phase {init_phase} --dry-run --config {temp_config}')

            defer.sudo(tmp_dirs_cmd, callback=new_tmp_dirs)

    control_planes.flush()

    stored_manifest = CollectorCallback(cluster)
    generated_manifest = CollectorCallback(cluster)
    for defer in control_planes.get_ordered_members_list():
        old_tmp_dirs_results = old_tmp_dirs.results[defer.get_host()]
        new_tmp_dirs_results = new_tmp_dirs.results[defer.get_host()]
        for i, component in enumerate(components):
            tmp_dir = next(iter(
                set(new_tmp_dirs_results[i].stdout.split())
                - set(old_tmp_dirs_results[i].stdout.split())
            ))
            defer.sudo(f'cat /etc/kubernetes/manifests/{component}.yaml', callback=stored_manifest)
            defer.sudo(f'cat /etc/kubernetes/tmp/{tmp_dir}/{component}.yaml', callback=generated_manifest)

    control_planes.flush()

    result: Dict[str, Dict[str, Optional[str]]] = {}
    for host in control_planes.get_hosts():
        stored_manifest_results = stored_manifest.results[host]
        generated_manifest_results = generated_manifest.results[host]
        for i, component in enumerate(components):
            tofile = (f"{component}.yaml generated from 'services.kubeadm' section"
                      if with_inventory
                      else f"{component}.yaml generated from kubeadm-config ConfigMap")
            stored = stored_manifest_results[i].stdout
            generated = generated_manifest_results[i].stdout
            if component == 'etcd':
                stored = _filter_etcd_initial_cluster_args(stored)
                generated = _filter_etcd_initial_cluster_args(generated)

            diff = utils.get_yaml_diff(stored, generated,
                                       fromfile=f'/etc/kubernetes/manifests/{component}.yaml',
                                       tofile=tofile)

            result.setdefault(host, {})[component] = diff

    return result


def compare_kubelet_config(cluster: KubernetesCluster, *, with_inventory: bool) \
        -> Dict[str, Optional[str]]:
    """
    Generate /var/lib/kubelet/config.yaml in dry-run mode on all nodes,
    and compare with already present configurations.

    :param cluster: KubernetesCluster instance
    :param with_inventory: flag if patches should be taken from the inventory
    :return: mapping host -> diff string
    """
    nodes = cluster.make_group_from_roles(['control-plane', 'worker']).new_defer()
    patches_dir = '/etc/kubernetes/patches'
    if with_inventory:
        patches_dir = utils.get_remote_tmp_path()

    tmp_dirs_cmd = "sh -c 'sudo ls /etc/kubernetes/tmp/ | grep dryrun 2>/dev/null || true'"
    old_tmp_dirs = CollectorCallback(cluster)
    new_tmp_dirs = CollectorCallback(cluster)
    for defer in nodes.get_ordered_members_list():
        if with_inventory:
            defer.sudo(f'mkdir -p {patches_dir}')
            _create_kubeadm_patches_for_component_on_node(
                cluster, defer, 'kubelet', patches_dir=patches_dir, reset=False)

        defer.sudo(tmp_dirs_cmd, callback=old_tmp_dirs)
        defer.sudo(f'kubeadm upgrade node phase kubelet-config --dry-run --patches={patches_dir}')
        defer.sudo(tmp_dirs_cmd, callback=new_tmp_dirs)

    nodes.flush()

    stored_config = CollectorCallback(cluster)
    generated_config = CollectorCallback(cluster)
    for defer in nodes.get_ordered_members_list():
        old_tmp_dirs_results = old_tmp_dirs.results[defer.get_host()]
        new_tmp_dirs_results = new_tmp_dirs.results[defer.get_host()]
        tmp_dir = next(iter(
            set(new_tmp_dirs_results[0].stdout.split())
            - set(old_tmp_dirs_results[0].stdout.split())
        ))
        defer.sudo(f'cat /var/lib/kubelet/config.yaml', callback=stored_config)
        defer.sudo(f'cat /etc/kubernetes/tmp/{tmp_dir}/config.yaml', callback=generated_config)

    nodes.flush()

    result = {}
    for host in nodes.get_hosts():
        tofile = (f"config.yaml with patches from inventory"
                  if with_inventory
                  else f"config.yaml generated from kubelet-config ConfigMap")
        stored = stored_config.results[host][0].stdout
        generated = generated_config.results[host][0].stdout

        diff = utils.get_yaml_diff(stored, generated,
                                   fromfile='/var/lib/kubelet/config.yaml',
                                   tofile=tofile)

        result[host] = diff

    return result


def compare_configmap(cluster: KubernetesCluster, configmap: str) -> Optional[str]:
    control_plane = cluster.nodes['control-plane'].get_first_member()
    kubeadm_config = KubeadmConfig(cluster)

    if configmap == 'kubelet-config':
        # Do not check kubelet-config ConfigMap, because some properties may be deleted from KubeletConfiguration
        # if set to default, for example readOnlyPort: 0, protectKernelDefaults: false
        # Otherwise, the check would require to take into account all such default properties.
        if not kubeadm_extended_dryrun(cluster):
            return None

        # Use upload-config kubelet --dry-run to catch all inserted/updated/deleted properties.

        temp_config = utils.get_remote_tmp_path()
        patches_dir = utils.get_remote_tmp_path()

        defer = control_plane.new_defer()
        collector = CollectorCallback(cluster)

        _upload_config(cluster, defer, kubeadm_config, temp_config, patches_dir=patches_dir)
        defer.sudo(f'mkdir -p {patches_dir}')
        _create_kubeadm_patches_for_component_on_node(
            cluster, defer, 'kubelet', patches_dir=patches_dir, reset=False)

        init_phase = CONFIGMAPS_CONSTANTS[configmap]['init_phase']
        defer.sudo(f'kubeadm init phase {init_phase} --dry-run --config {temp_config}',
                   callback=collector)

        defer.flush()
        output = collector.result[control_plane.get_host()].stdout

        split_logs = re.compile(r'^\[.*].*$\n', flags=re.M)
        cfg = next(filter(lambda ln: 'kind: KubeletConfiguration' in ln, split_logs.split(output)))
        cfg = dedent(cfg)

        key = CONFIGMAPS_CONSTANTS[configmap]['key']
        generated_config = yaml.safe_load(cfg)['data'][key]
        if 'resolvConf' not in kubeadm_config.maps[configmap]:
            generated_config = _filter_kubelet_configmap_resolv_conf(generated_config)

        kubeadm_config.load(configmap, control_plane)
        # Use loaded_maps that preserve original formatting
        stored_config = kubeadm_config.loaded_maps[configmap].obj["data"][key]

        if yaml.safe_load(generated_config) == yaml.safe_load(stored_config):
            return None

        return utils.get_unified_diff(stored_config, generated_config,
                                      fromfile=f'{configmap} ConfigMap',
                                      tofile="generated from 'services.kubeadm_kubelet' section")

    else:
        # Merge with inventory and check.
        # This way it is possible to check only new or changed properties in the inventory
        # that are still not reflected in the remote ConfigMap.

        stored_config = kubeadm_config.load(configmap, control_plane)

        generated_config = kubeadm_config.merge_with_inventory(configmap)\
                (utils.deepcopy_yaml(stored_config))

        if generated_config == stored_config:
            return None

        section = CONFIGMAPS_CONSTANTS[configmap]['section']
        return utils.get_unified_diff(yaml.dump(stored_config), yaml.dump(generated_config),
                                      fromfile=f'{configmap} ConfigMap',
                                      tofile=f"{configmap} ConfigMap merged 'services.{section}' section")


def _detect_changes(logger: log.EnhancedLogger, old: str, new: str, fromfile: str, tofile: str) -> bool:
    diff = utils.get_yaml_diff(old, new, fromfile, tofile)
    if diff is not None:
        logger.debug(f"Detected changes in {tofile}")
        logger.verbose(diff)
        return True

    return False


def _filter_etcd_initial_cluster_args(content: str) -> str:
    return '\n'.join(ln for ln in content.splitlines() if '--initial-cluster' not in ln)


def _filter_kubelet_configmap_resolv_conf(content: str) -> str:
    return '\n'.join(ln for ln in content.splitlines() if 'resolvConf:' not in ln)


def _restart_containers(cluster: KubernetesCluster, node: NodeGroup, components: Sequence[str]) -> None:
    if not components:
        return

    logger = cluster.log
    node_name = node.get_node_name()
    logger.debug(f"Restarting containers for components {list(components)} on node: {node_name}")

    commands = []

    # Take into account probably missed container because kubelet may be restarting them at this moment.
    # Though still ensure the command to delete the container successfully if it is present.
    restart_container = ("(set -o pipefail && sudo crictl ps --name {component} -q "
                         "| xargs -I CONTAINER sudo crictl rm -f CONTAINER) > /dev/null")

    for component in components:
        commands.append(restart_container.format(component=component))

    get_container_from_cri = "sudo crictl ps --name {component} -q"
    get_container_from_pod = (
        "sudo kubectl get pods -n kube-system {component}-{node} "
        "-o 'jsonpath={{.status.containerStatuses[0].containerID}}{{\"\\n\"}}' "
        "| sed 's|.\\+://\\(.\\+\\)|\\1|'")

    # Wait for kubelet to refresh container status in pods.
    # It is expected that Ready status will be refreshed at the same time,
    # so we can safely wait_for_pods().
    test_refreshed_container = (
        f"("
        f"CONTAINER=$({get_container_from_cri}); "
        f"if [ -z \"$CONTAINER\" ]; then "
        f"  echo \"container '{{component}}' is not created yet\" >&2 ; exit 1; "
        f"fi "
        f"&& "
        f"if [ \"$CONTAINER\" != \"$({get_container_from_pod})\" ]; "
        f"  then echo \"Pod '{{component}}-{{node}}' is not refreshed yet\" >&2; exit 1; "
        f"fi "
        f")")

    for component in components:
        commands.append(test_refreshed_container.format(component=component, node=node_name))

    expect_config = cluster.inventory['globals']['expect']['pods']['kubernetes']
    node.wait_commands_successful(commands,
                                  timeout=expect_config['timeout'],
                                  retries=expect_config['retries'],
                                  sudo=False, pty=True)


def _delete_pods(cluster: KubernetesCluster, node: AbstractGroup[RunResult],
                 control_plane: NodeGroup, components: Sequence[str]) -> None:
    if not components:
        return

    node_name = node.get_node_name()
    cluster.log.debug(f"Deleting pods for components {list(components)} on node: {node_name}")

    restart_pod = (
        "kubectl delete pod -n kube-system $("
        "    sudo kubectl get pods -n kube-system -o=wide "
        "    | grep '{pod}' | grep '{node}' | awk '{{ print $1 }}'"
        ")"
    )

    defer = control_plane.new_defer()
    for component in components:
        defer.sudo(restart_pod.format(pod=component, node=node_name))

    defer.flush()


# function to get dictionary of flags to be patched for a given control plane item and a given node
def get_patched_flags_for_section(cluster: KubernetesCluster,
                                  patch_section: str, group: AbstractGroup[RunResult]) -> Dict[str, Union[str, bool, int]]:
    node = group.get_config()
    flags = {}

    for n in cluster.inventory['services']['kubeadm_patches'][patch_section]:
        group = cluster.create_group_from_groups_nodes_names(
            n.get('groups', []), n.get('nodes', []))

        if group.has_node(node['name']):
            for arg, value in n['patch'].items():
                flags[arg] = value

    # we always set binding-address to the node's internal address for apiServer
    if patch_section == 'apiServer' and 'control-plane' in node['roles']:
        flags['bind-address'] = node['internal_address']

    return flags


def _create_kubeadm_patches_for_component_on_node(cluster: KubernetesCluster, node: DeferredGroup, component: str,
                                                  backup_dir: Optional[str] = None,
                                                  *, patches_dir: str = '/etc/kubernetes/patches', reset: bool = True) -> None:
    patch_constants = COMPONENTS_CONSTANTS[component]['patch']
    component_patches = f"find {patches_dir} -name {patch_constants['target_template']}"

    if backup_dir is not None:
        node.sudo(f'{component_patches} -exec cp {{}} {backup_dir}/patches \\;')

    if reset:
        node.sudo(f'{component_patches} -delete')

    # read patch content from inventory and upload patch files to a node
    patched_flags = get_patched_flags_for_section(cluster, patch_constants['section'], node)
    if patched_flags:
        if component == 'kubelet':
            template_filename = 'templates/patches/kubelet.yaml.j2'
        else:
            template_filename = 'templates/patches/control-plane-pod.json.j2'

        control_plane_patch = Template(utils.read_internal(template_filename)).render(flags=patched_flags)
        patch_file = patches_dir + '/' + patch_constants['file']
        node.put(io.StringIO(control_plane_patch + "\n"), patch_file, sudo=True)
        node.sudo(f'chmod 644 {patch_file}')
