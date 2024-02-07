import io
from typing import List, Optional, Dict, Callable, Sequence

import yaml
from jinja2 import Template
from ordered_set import OrderedSet

from kubemarine import plugins, system
from kubemarine.core import utils, log
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeConfig, NodeGroup, DeferredGroup, CollectorCallback, AbstractGroup, RunResult
from kubemarine.core.yaml_merger import override_merger
from kubemarine.kubernetes.object import KubernetesObject

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


class _KubeadmConfig:
    def __init__(self, cluster: KubernetesCluster):
        self.cluster = cluster

        inventory = cluster.inventory
        self.maps: Dict[str, dict] = {
            configmap: inventory["services"][constants['section']]
            for configmap, constants in CONFIGMAPS_CONSTANTS.items()}

        self.edited_maps: Dict[str, KubernetesObject] = {}

    def is_edited(self, configmap: str) -> bool:
        return configmap in self.edited_maps

    def edit(self, configmap: str, edit_func: Callable[[dict], dict], control_plane: NodeGroup) -> None:
        """
        Load ConfigMap as object, retrieve plain config from it, and apply `edit_func` to the plain config.

        :param configmap: name of ConfigMap
        :param edit_func: function to apply changes
        :param control_plane: Use this control plane node to fetch the ConfigMap.
        """
        configmap_obj = KubernetesObject(self.cluster, 'ConfigMap', configmap, 'kube-system')
        configmap_obj.reload(control_plane)

        self.edited_maps[configmap] = configmap_obj

        key = CONFIGMAPS_CONSTANTS[configmap]['key']
        config: dict = yaml.safe_load(configmap_obj.obj["data"][key])

        config = edit_func(config)
        configmap_obj.obj["data"][key] = yaml.dump(config)

        self.maps[configmap] = config

    def apply(self, configmap: str, control_plane: NodeGroup) -> None:
        """
        Apply ConfigMap that was previously changed using edit().

        :param configmap: name of ConfigMap
        :param control_plane: Use this control plane node to apply the ConfigMap.
        :return:
        """
        if not self.is_edited(configmap):
            raise ValueError(f"To apply changed {configmap} ConfigMap, it is necessary to fetch it first")

        self.edited_maps[configmap].apply(control_plane)

    def to_yaml(self, init_config: dict) -> str:
        configs = list(self.maps.values())
        configs.append(init_config)
        return yaml.dump_all(configs)


def kubelet_config_unversioned(cluster: KubernetesCluster) -> bool:
    return kubernetes_minor_release_at_least(cluster.inventory, "v1.24")


def kubelet_supports_patches(cluster: KubernetesCluster) -> bool:
    return kubernetes_minor_release_at_least(cluster.inventory, "v1.25")


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

    if inventory['services']['kubeadm']['controllerManager']['extraArgs'].get('external-cloud-volume-plugin'):
        init_config['nodeRegistration'] = {
            'kubeletExtraArgs': {
                'cloud-provider': 'external'
            }
        }

    if control_plane and worker:
        init_config.setdefault('nodeRegistration', {})['taints'] = []

    _configure_container_runtime(cluster, init_config)

    return init_config


def get_kubeadm_config(cluster: KubernetesCluster, init_config: dict) -> str:
    return _KubeadmConfig(cluster).to_yaml(init_config)


def _configure_container_runtime(cluster: KubernetesCluster, kubeadm_config: dict) -> None:
    if cluster.inventory['services']['cri']['containerRuntime'] == "containerd":
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

    :param group: nodes to reconfigure components on
    :param components: List of control plane components or `kube-proxy`, or `kubelet` to reconfigure.
    :param edit_functions: Callables that edit the specified kubeadm-managed ConfigMaps in a custom way.
                           The ConfigMaps are fetched from the first control plane,
                           instead of being generated.
                           This implies necessity of working API server.
    :param force_restart: Restart the given `components` even if nothing has changed in their configuration.
    """
    if edit_functions is None:
        edit_functions = {}

    cluster: KubernetesCluster = group.cluster
    logger = cluster.log
    control_plane = cluster.nodes['control-plane'].get_first_member()

    timestamp = utils.get_current_timestamp_formatted()
    backup_dir = '/etc/kubernetes/tmp/kubemarine-backup-' + timestamp
    logger.debug(f"Using backup directory {backup_dir}")

    logger.debug("Uploading cluster config to first control plane...")

    kubeadm_config = _KubeadmConfig(cluster)
    for configmap, func in edit_functions.items():
        kubeadm_config.edit(configmap, func, control_plane)

    # This configuration will be used for `kubeadm init phase upload-config` phase.
    # InitConfiguration is necessary to specify patches directory.
    # Use patches from the first control plane, to make it the same as during regular installation.
    # Patches are used to upload KubeletConfiguration for some reason (which is likely a gap)
    # https://github.com/kubernetes/kubernetes/issues/123090
    upload_config = '/etc/kubernetes/upload-config.yaml'
    _upload_config(cluster, control_plane, kubeadm_config, upload_config)

    control_plane_components = [
        c for c in components
        if c in ('kube-apiserver/cert-sans', 'kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd')]

    # Firstly reconfigure components that do not require working API server
    if control_plane_components:
        if _reconfigure_control_plane_components(cluster, group, control_plane_components, force_restart,
                                                 kubeadm_config, backup_dir):
            _update_configmap(cluster, control_plane, 'kubeadm-config',
                              _configmap_init_phase_uploader('kubeadm-config', upload_config),
                              backup_dir)

    node_components = [c for c in components if c in ('kubelet', 'kube-proxy')]

    if node_components:
        _reconfigure_node_components(cluster, group, node_components, force_restart, control_plane,
                                     upload_config, kubeadm_config, backup_dir)


def restart_components(group: NodeGroup, components: List[str]) -> None:
    """
    Currently it is supported to restart only
    'kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd'.

    :param group: nodes to restart components on
    :param components: Kubernetes components to restart
    """
    cluster: KubernetesCluster = group.cluster

    for node in group.get_ordered_members_list():
        is_control_plane = 'control-plane' in node.get_config()['roles']
        _components = [c for c in components if is_control_plane and c in CONTROL_PLANE_COMPONENTS]

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
    if components is not None and len(components) == 0:
        return

    cluster: KubernetesCluster = group.cluster
    first_control_plane = cluster.nodes['all'].get_first_member()
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
                _components.extend([
                    'kube-apiserver',
                    'kube-controller-manager',
                    'kube-scheduler',
                    'etcd'
                ])

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
    for component in ('kube-apiserver', 'kube-scheduler', 'kube-controller-manager', 'etcd', 'kubelet'):
        _create_kubeadm_patches_for_component_on_node(cluster, defer, component)

    defer.flush()


def _upload_config(cluster: KubernetesCluster, control_plane: AbstractGroup[RunResult],
                   kubeadm_config: _KubeadmConfig, remote_path: str) -> None:
    name = remote_path.rstrip('.yaml').split('/')[-1]

    init_config = get_init_config(cluster, control_plane, init=True)
    config = kubeadm_config.to_yaml(init_config)
    utils.dump_file(cluster, config, f"{name}_{control_plane.get_node_name()}.yaml")

    control_plane.put(io.StringIO(config), remote_path, sudo=True)


def _update_configmap(cluster: KubernetesCluster, control_plane: NodeGroup, configmap: str,
                      uploader: Callable[[DeferredGroup], None], backup_dir: str) -> bool:
    logger = cluster.log

    logger.debug(f"Updating {configmap} ConfigMap")
    defer = control_plane.new_defer()
    collector = CollectorCallback(cluster)

    configmap_name = configmap
    if configmap == 'kubelet-config' and not kubelet_config_unversioned(cluster):
        kubernetes_version = cluster.inventory["services"]["kubeadm"]["kubernetesVersion"]
        configmap_name += '-' + utils.minor_version(kubernetes_version)[1:]

    key = CONFIGMAPS_CONSTANTS[configmap]['key'].replace('.', r'\.')
    configmap_cmd = f'sudo kubectl get cm -n kube-system {configmap_name} -o=jsonpath="{{.data.{key}}}"'

    # backup
    defer.run(f'sudo mkdir -p {backup_dir}')
    backup_file = f'{backup_dir}/{configmap_name}.yaml'
    defer.run(f'(set -o pipefail && {configmap_cmd} | sudo tee {backup_file}) > /dev/null')

    # update
    uploader(defer)

    # compare
    defer.run(f'sudo cat {backup_file}', callback=collector)
    defer.run(configmap_cmd, callback=collector)

    defer.flush()

    results = collector.results[defer.get_host()]
    return _detect_changes(logger, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=f'{configmap_name} ConfigMap')


def _configmap_init_phase_uploader(configmap: str, upload_config: str) -> Callable[[DeferredGroup], None]:
    def upload(control_plane: DeferredGroup) -> None:
        init_phase = CONFIGMAPS_CONSTANTS[configmap]['init_phase']
        control_plane.run(f'sudo kubeadm init phase {init_phase} --config {upload_config}')

    return upload


def _kube_proxy_configmap_uploader(cluster: KubernetesCluster, kubeadm_config: _KubeadmConfig) \
        -> Callable[[DeferredGroup], None]:

    # Unfortunately, there is no suitable kubeadm command to upload the generated ConfigMap.
    # This makes it impossible to reset some property to default by deleting it from `services.kubeadm_kube-proxy`.

    def upload(control_plane_deferred: DeferredGroup) -> None:
        control_plane_deferred.flush()
        control_plane = cluster.make_group(control_plane_deferred.get_hosts())

        # reconfigure_components() can be called with custom editing function.
        # The ConfigMap is already fetched and changed.
        if not kubeadm_config.is_edited('kube-proxy'):
            def merge_with_inventory(config_: dict) -> dict:
                patch_config: dict = kubeadm_config.maps['kube-proxy']
                # Since default configuration does not have non-empty lists, override merger seems the most suitable.
                config_ = override_merger.merge(config_, patch_config)
                return config_

            kubeadm_config.edit('kube-proxy', merge_with_inventory, control_plane)

        # Apply updated kube-proxy ConfigMap
        kubeadm_config.apply('kube-proxy', control_plane)

    return upload


def _reconfigure_control_plane_components(cluster: KubernetesCluster, group: NodeGroup, components: List[str],
                                          force_restart: bool,
                                          kubeadm_config: _KubeadmConfig, backup_dir: str) -> bool:
    logger = cluster.log

    candidate_group = cluster.nodes['control-plane']
    group = group.intersection_group(candidate_group)

    if group.is_empty():
        logger.debug("No control plane nodes to reconfigure control plane components")
        return False

    reconfigure_config = '/etc/kubernetes/reconfigure-config.yaml'

    patch_group = group.new_defer()
    for defer in patch_group.get_ordered_members_list():
        logger.debug(f"Uploading config for control plane components on node: {defer.get_node_name()}")
        _upload_config(cluster, defer, kubeadm_config, reconfigure_config)

        if components != ['kube-apiserver/cert-sans']:
            defer.sudo("mkdir -p /etc/kubernetes/patches")
            defer.sudo(f'mkdir -p {backup_dir}/patches')
            defer.sudo(f'mkdir -p {backup_dir}/manifests')

        for component in components:
            if component == 'kube-apiserver/cert-sans':
                continue

            _create_kubeadm_patches_for_component_on_node(cluster, defer, component, backup_dir)

    patch_group.flush()

    for node in group.get_ordered_members_list():
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

    return True


def _reconfigure_apiserver_certsans(node: DeferredGroup, reconfigure_config: str, backup_dir: str) -> None:
    apiserver_certs = r'find /etc/kubernetes/pki/ -name apiserver.\*'

    # backup
    node.sudo(f'mkdir -p {backup_dir}/pki')
    node.sudo(f'{apiserver_certs} -exec cp {{}} {backup_dir}/pki \\;')

    # create cert
    node.sudo(f'{apiserver_certs} -delete')
    init_phase = COMPONENTS_CONSTANTS['kube-apiserver/cert-sans']['init_phase']
    node.sudo(f'kubeadm init phase {init_phase} --config {reconfigure_config}')


def _reconfigure_control_plane_component(cluster: KubernetesCluster, node: DeferredGroup, component: str,
                                         reconfigure_config: str, backup_dir: str) -> bool:
    manifest = f'/etc/kubernetes/manifests/{component}.yaml'
    backup_file = f'{backup_dir}/manifests/{component}.yaml'
    collector = CollectorCallback(cluster)

    # backup
    node.sudo(f"cp {manifest} {backup_file}")

    # update
    init_phase = COMPONENTS_CONSTANTS[component]['init_phase']
    node.sudo(f'kubeadm init phase {init_phase} --config {reconfigure_config}')

    # compare
    node.sudo(f'cat {backup_file}', callback=collector)
    node.sudo(f'cat {manifest}', callback=collector)

    node.flush()

    results = collector.results[node.get_host()]
    return _detect_changes(cluster.log, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=manifest)


def _reconfigure_node_components(cluster: KubernetesCluster, group: NodeGroup, components: List[str],
                                 force_restart: bool, control_plane: NodeGroup,
                                 upload_config: str, kubeadm_config: _KubeadmConfig, backup_dir: str) -> None:
    logger = cluster.log

    control_planes = (cluster.nodes['control-plane']
                      .intersection_group(group))
    workers = (cluster.make_group_from_roles(['worker'])
               .exclude_group(control_planes)
               .intersection_group(group))

    nodes = workers.get_ordered_members_list() + control_planes.get_ordered_members_list()

    if not nodes:
        logger.debug("No Kubernetes nodes to reconfigure components")
        return

    if 'kubelet' in components:
        patch_group = (workers.include_group(control_planes)
                       .include_group(control_plane)  # first control plane will be used to upload config
                       .new_defer())

        for defer in patch_group.get_ordered_members_list():
            defer.sudo("mkdir -p /etc/kubernetes/patches")
            defer.sudo(f'mkdir -p {backup_dir}/patches')
            _create_kubeadm_patches_for_component_on_node(cluster, defer, 'kubelet', backup_dir)

        patch_group.flush()

        _update_configmap(cluster, control_plane, 'kubelet-config',
                          _configmap_init_phase_uploader('kubelet-config', upload_config),
                          backup_dir)

    kube_proxy_changed = False
    if 'kube-proxy' in components:
        kube_proxy_changed = _update_configmap(cluster, control_plane, 'kube-proxy',
                                               _kube_proxy_configmap_uploader(cluster, kubeadm_config),
                                               backup_dir)

    for node in nodes:
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
    patches_flag = ' --patches=/etc/kubernetes/patches' if kubelet_supports_patches(cluster) else ''
    node.sudo(f'kubeadm upgrade node phase kubelet-config{patches_flag}')

    # compare
    node.sudo(f'cat {backup_file}', callback=collector)
    node.sudo(f'cat {config}', callback=collector)

    node.flush()

    results = collector.results[node.get_host()]
    return _detect_changes(cluster.log, results[0].stdout, results[1].stdout,
                           fromfile=backup_file, tofile=config)


def _detect_changes(logger: log.EnhancedLogger, old: str, new: str, fromfile: str, tofile: str) -> bool:
    if yaml.safe_load(old) == yaml.safe_load(new):
        return False

    diff = utils.get_unified_diff(old, new, fromfile, tofile)
    if diff is not None:
        logger.debug(f"Detected changes in {tofile}")
        logger.verbose(diff)

    return True


def _restart_containers(cluster: KubernetesCluster, node: NodeGroup, components: Sequence[str]) -> None:
    if not components:
        return

    logger = cluster.log
    node_name = node.get_node_name()
    logger.debug(f"Restarting containers for components {list(components)} on node: {node_name}")

    commands = []

    cri_impl = cluster.inventory['services']['cri']['containerRuntime']
    # Take into account probably missed container because kubelet may be restarting them at this moment.
    # Though still ensure the command to delete the container successfully if it is present.
    if cri_impl == 'containerd':
        restart_container = ("(set -o pipefail && sudo crictl ps --name {component} -q "
                             "| xargs -I CONTAINER sudo crictl rm -f CONTAINER)")
    else:
        restart_container = ("(set -o pipefail && sudo docker ps -q -f 'name=k8s_{component}' "
                             "| xargs -I CONTAINER sudo docker rm -f CONTAINER)")

    for component in components:
        commands.append(restart_container.format(component=component))

    if cri_impl == 'containerd':
        get_container_from_cri = "sudo crictl ps --name {component} -q"
    else:
        get_container_from_cri = (
            "sudo docker ps --no-trunc -f 'name=k8s_{component}' "
            "| grep k8s_{component} | awk '{{{{ print $1 }}}}'")

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
                                  sudo=False)


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
def _get_patched_flags_for_section(inventory: dict, patch_section: str, node: NodeConfig) -> Dict[str, str]:
    flags = {}

    for n in inventory['services']['kubeadm_patches'][patch_section]:
        if n.get('groups') is not None and list(set(node['roles']) & set(n['groups'])):
            for arg, value in n['patch'].items():
                flags[arg] = value
        if n.get('nodes') is not None and node['name'] in n['nodes']:
            for arg, value in n['patch'].items():
                flags[arg] = value

    # we always set binding-address to the node's internal address for apiServer
    if patch_section == 'apiServer' and 'control-plane' in node['roles']:
        flags['bind-address'] = node['internal_address']

    return flags


def _create_kubeadm_patches_for_component_on_node(cluster: KubernetesCluster, node: DeferredGroup, component: str,
                                                  backup_dir: Optional[str] = None) -> None:
    patch_constants = COMPONENTS_CONSTANTS[component]['patch']
    component_patches = f"find /etc/kubernetes/patches -name {patch_constants['target_template']}"

    if backup_dir is not None:
        node.sudo(f'{component_patches} -exec cp {{}} {backup_dir}/patches \\;')

    node.sudo(f'{component_patches} -delete')

    # read patch content from inventory and upload patch files to a node
    node_config = node.get_config()
    patched_flags = _get_patched_flags_for_section(cluster.inventory, patch_constants['section'], node_config)
    if patched_flags:
        if component == 'kubelet':
            template_filename = 'templates/patches/kubelet.yaml.j2'
        else:
            template_filename = 'templates/patches/control-plane-pod.json.j2'

        control_plane_patch = Template(utils.read_internal(template_filename)).render(flags=patched_flags)
        patch_file = '/etc/kubernetes/patches/' + patch_constants['file']
        node.put(io.StringIO(control_plane_patch + "\n"), patch_file, sudo=True)
        node.sudo(f'chmod 644 {patch_file}')
