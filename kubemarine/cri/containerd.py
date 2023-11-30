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
from copy import deepcopy
from io import StringIO
from typing import Dict, List, Tuple, Optional

import toml
import yaml
import base64

from kubemarine import system, packages
from kubemarine.core import utils, static, errors
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback
from kubemarine.core.yaml_merger import default_merger


def enrich_inventory(inventory: dict, _: KubernetesCluster) -> dict:
    containerd_config = inventory['services']['cri']['containerdConfig']

    path = 'plugins."io.containerd.grpc.v1.cri"'
    kubernetes_version = inventory['services']['kubeadm']['kubernetesVersion']
    containerd_config[path].setdefault('sandbox_image', get_default_sandbox_image(inventory, kubernetes_version))

    runc_options_path = f'{path}.containerd.runtimes.runc.options'
    if not isinstance(containerd_config[runc_options_path]['SystemdCgroup'], bool):
        containerd_config[runc_options_path]['SystemdCgroup'] = \
            utils.strtobool(containerd_config[runc_options_path]['SystemdCgroup'], "containerdConfig.SystemdCgroup")

    # Check if field for new and old configuration formats are presented
    old_format_result, old_format_field = contains_old_format_properties(inventory)
    new_format_result, new_format_field = contains_new_format_properties(inventory)

    # Fail if fields for both formats are presented
    if old_format_result and new_format_result:
        raise errors.FailException(f"Invalid containerd configuration: "
                                   f"{old_format_field} can't be set when {new_format_field} is provided")

    # If no fields for old format, enrich config_path default value to new format
    if not old_format_result and 'containerdRegistriesConfig' in inventory['services']['cri']:
        containerd_config.setdefault('plugins."io.containerd.grpc.v1.cri".registry', {})\
            .setdefault('config_path', '/etc/containerd/certs.d')
    return inventory


def contains_old_format_properties(inventory: dict) -> Tuple[bool, Optional[str]]:
    config_toml = get_config_as_toml(inventory.get("services", {}).get("cri", {}).get('containerdConfig', {}))
    if "mirrors" in config_toml.get("plugins", {}).get("io.containerd.grpc.v1.cri", {}).get("registry", {}):
        return True, 'mirrors for "io.containerd.grpc.v1.cri" plugin in services.cri.containerdConfig'
    for _, config in config_toml.get("plugins", {}).get("io.containerd.grpc.v1.cri", {})\
            .get("registry", {}).get("configs", {}).items():
        if "tls" in config:
            return True, 'configs.tls for "io.containerd.grpc.v1.cri" plugin in services.cri.containerdConfig'
    return False, None


def contains_new_format_properties(inventory: dict) -> Tuple[bool, Optional[str]]:
    config_toml = get_config_as_toml(inventory.get("services", {}).get("cri", {}).get('containerdConfig', {}))
    if "config_path" in config_toml.get("plugins", {}).get("io.containerd.grpc.v1.cri", {}).get("registry", {}):
        return True, 'config_path for "io.containerd.grpc.v1.cri" plugin in services.cri.containerdConfig'
    if inventory.get('services', {}).get('cri', {}).get('containerdRegistriesConfig', {}):
        return True, 'services.cri.containerdRegistriesConfig'
    return False, None


def get_default_sandbox_image(inventory: dict, kubernetes_version: str) -> str:
    image_repository = inventory['services']['kubeadm']['imageRepository']
    pause_version = static.GLOBALS['compatibility_map']['software']['pause'][kubernetes_version]['version']
    return f"{image_repository}/pause:{pause_version}"


def get_sandbox_image(cri_config: dict) -> Optional[str]:
    sandbox_image: Optional[str] = cri_config.get('containerdConfig', {})\
        .get('plugins."io.containerd.grpc.v1.cri"', {}).get('sandbox_image')

    return sandbox_image


def get_sandbox_image_upgrade_plan(cluster: KubernetesCluster) -> List[Tuple[str, dict]]:
    context = cluster.context
    upgrade_plan = []
    if context.get("initial_procedure") == "upgrade":
        upgrade_version = context["upgrade_version"]
        for version in cluster.procedure_inventory['upgrade_plan']:
            if utils.version_key(version) < utils.version_key(upgrade_version):
                continue

            upgrade_config = cluster.procedure_inventory.get(version, {}).get('cri', {})
            upgrade_plan.append((version, upgrade_config))

    return upgrade_plan


def enrich_upgrade_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    upgrade_plan = get_sandbox_image_upgrade_plan(cluster)
    if not upgrade_plan:
        return inventory

    context = cluster.context
    previous_version = context["initial_kubernetes_version"]
    sandbox_image = get_sandbox_image(inventory['services']['cri'])
    for version, upgrade_config in upgrade_plan:
        upgrade_sandbox_image = get_sandbox_image(upgrade_config)
        if sandbox_image is not None and upgrade_sandbox_image is None:
            raise errors.KME("KME0013",
                             previous_version_spec=f' for version {previous_version}',
                             next_version_spec=f' for version {version}')

        sandbox_image = upgrade_sandbox_image
        previous_version = version

    context.setdefault("upgrade", {}).setdefault('required', {})['containerdConfig'] \
        = is_sandbox_image_upgrade_required(cluster, inventory)

    return upgrade_finalize_inventory(cluster, inventory)


def is_sandbox_image_upgrade_required(cluster: KubernetesCluster, inventory: dict) -> bool:
    previous_ver = cluster.context["initial_kubernetes_version"]
    old_image = get_sandbox_image(inventory['services']['cri'])
    if old_image is None:
        old_image = get_default_sandbox_image(inventory, previous_ver)

    upgrade_ver = inventory['services']['kubeadm']['kubernetesVersion']
    _, upgrade_config = get_sandbox_image_upgrade_plan(cluster)[0]
    new_image = get_sandbox_image(upgrade_config)
    if new_image is None:
        new_image = get_default_sandbox_image(inventory, upgrade_ver)

    return old_image != new_image


def upgrade_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    upgrade_plan = get_sandbox_image_upgrade_plan(cluster)
    if not upgrade_plan:
        return inventory

    _, upgrade_config = upgrade_plan[0]
    if upgrade_config:
        default_merger.merge(inventory.setdefault("services", {}).setdefault("cri", {}), upgrade_config)

    return inventory


def enrich_migrate_cri_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:
    # This method should be before defaults.apply_registry
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory

    if inventory["services"]["cri"]["containerRuntime"] == cluster.procedure_inventory["cri"]["containerRuntime"]:
        raise Exception("You already have such cri or you should explicitly specify 'cri.containerRuntime: docker' in cluster.yaml")

    return migrate_cri_finalize_inventory(cluster, inventory)


def migrate_cri_finalize_inventory(cluster: KubernetesCluster, inventory: dict) -> dict:
    if cluster.context.get("initial_procedure") != "migrate_cri":
        return inventory

    cri_section = inventory.setdefault("services", {}).setdefault("cri", {})

    if cri_section.get("dockerConfig", {}):
        del cri_section["dockerConfig"]

    default_merger.merge(cri_section, deepcopy(cluster.procedure_inventory["cri"]))
    return inventory


def fetch_containerd_config(group: NodeGroup) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    cluster = group.cluster
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            config_location = cluster.get_package_association_for_node(node.get_host(),
                                                                       'containerd', 'config_location')
            node.sudo(f'cat {config_location}', callback=collector)

    containerd_config = {host: toml.loads(config_string.stdout)
                         for host, config_string in collector.result.items()}

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            config_path = containerd_config[node.get_host()]\
                .get('plugins', {})\
                .get('io.containerd.grpc.v1.cri', {}).get('registry', {}).get('config_path')
            if config_path:
                node.sudo(f'ls {config_path}', callback=collector)

    containerd_registries = {host: registries.stdout.split('\n')[:-1]
                             for host, registries in collector.result.items()}

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            config_path = containerd_config[node.get_host()] \
                .get('plugins', {}) \
                .get('io.containerd.grpc.v1.cri', {}).get('registry', {}).get('config_path')
            for registry in containerd_registries.get(node.get_host(), {}):
                node.sudo(f'cat {config_path}/{registry}/hosts.toml', callback=collector)

    containerd_reg_config = {host: {containerd_registries[host][i]: toml.loads(reg_host.stdout)
                                    for i, reg_host in enumerate(reg_hosts)}
                             for host, reg_hosts in collector.results.items()}

    return containerd_config, containerd_reg_config


def install(group: NodeGroup) -> RunnersGroupResult:
    collector = CollectorCallback(group.cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            os_specific_associations = exe.cluster.get_associations_for_node(node.get_host(), 'containerd')

            exe.cluster.log.debug("Installing latest containerd on %s node" % node.get_node_name())
            # always install latest available containerd
            packages.install(node, include=os_specific_associations['package_name'], callback=collector)

            # remove previous config.toml to avoid problems in case when previous config was broken
            node.sudo("rm -f %s && sudo systemctl restart %s"
                      % (os_specific_associations['config_location'],
                         os_specific_associations['service_name']),
                      callback=collector)

            system.enable_service(node, os_specific_associations['service_name'],
                                  now=True, callback=collector)
    return collector.result


def get_config_as_toml(config: dict) -> dict:
    config_string = ''
    # double loop is used to make sure that no "simple" `key: value` pairs are accidentally assigned to sections
    for key, value in config.items():
        # first we process all "simple" `key: value` pairs
        if not isinstance(value, dict):
            config_string += f"{toml.dumps({key: value})}"
    for key, value in config.items():
        # next we process all "complex" `key: dict_value` pairs, representing named sections
        if isinstance(value, dict):
            config_string += f"\n[{key}]\n{toml.dumps(value)}"

    return toml.loads(config_string)


def configure_ctr_flags(group: NodeGroup) -> None:
    cluster = group.cluster
    log = cluster.log
    config_toml = get_config_as_toml(cluster.inventory.get("services", {}).get("cri", {}).get('containerdConfig', {}))
    # Calculate ctr options for image pull
    registry = config_toml.get('plugins', {}).get('io.containerd.grpc.v1.cri', {}).get('registry', {})
    config_path = registry.get('config_path')
    ctr_pull_options_str = ""
    for registry_name in set().union(registry.get('mirrors', {}).keys(), registry.get('configs', {}).keys()):
        options = []
        # Add plain-http flag for http endpoint
        if any("http://" in endpoint for endpoint in
               registry.get('mirrors', {}).get(registry_name, {}).get('endpoint', [])):
            options.append('--plain-http')
        # Add skip-verify flag in case of insecure tls connection
        if registry.get('configs', {}).get(registry_name, {}).get('tls', {}).get('insecure_skip_verify', False):
            options.append('--skip-verify')
        # Add user flag if authorization required
        registry_auth = registry.get('configs', {}).get(registry_name, {}).get('auth', {})
        if registry_auth.get('auth'):
            options.append(f'--user {base64.b64decode(registry_auth["auth"]).decode("utf-8")}')
        elif registry_auth.get('username'):
            options.append(f'--user {registry_auth["username"]}' +
                           f':{registry_auth["password"]}' if registry_auth.get("password") else '')
        ctr_pull_options_str += f'{registry_name}={" ".join(options)}\n'

    # Add hosts-dir, if it's presented
    if config_path:
        ctr_pull_options_str += f'*=--hosts-dir {config_path}\n'

    # Save ctr pull options
    log.debug("Uploading ctr flags configuration...")
    group.put(StringIO(ctr_pull_options_str), "/etc/ctr/kubemarine_ctr_flags.conf", backup=True, sudo=True, mkdir=True)
    group.sudo("chmod 600 /etc/ctr/kubemarine_ctr_flags.conf")


def configure_crictl(group: NodeGroup) -> None:
    cluster = group.cluster
    cluster.log.debug("Uploading crictl configuration for containerd...")
    crictl_config = yaml.dump({"runtime-endpoint": "unix:///run/containerd/containerd.sock"})
    utils.dump_file(cluster, crictl_config, 'crictl.yaml')
    group.put(StringIO(crictl_config), '/etc/crictl.yaml', backup=True, sudo=True)


def get_config_path(inventory: dict) -> Optional[str]:
    config_path: Optional[str] = inventory.get('services', {}).get('cri', {}).get('containerdConfig', {}) \
        .get('plugins."io.containerd.grpc.v1.cri".registry', {}).get('config_path')
    return config_path


def configure_containerd(group: NodeGroup) -> RunnersGroupResult:
    cluster = group.cluster
    log = cluster.log

    # Dump containerd configuration
    config_toml = get_config_as_toml(cluster.inventory.get("services", {}).get("cri", {}).get('containerdConfig', {}))
    config_string = toml.dumps(config_toml)
    utils.dump_file(cluster, config_string, 'containerd-config.toml')
    config_path = config_toml.get('plugins', {}).get('io.containerd.grpc.v1.cri', {})\
        .get('registry', {}).get('config_path')

    # Dump registries configuration
    registries_config = {}
    for registry, host_config in cluster.inventory.get("services", {}).get("cri", {})\
            .get('containerdRegistriesConfig', {}).items():
        registry_host_toml = get_config_as_toml(host_config)
        registries_config[registry] = toml.dumps(registry_host_toml)
        utils.dump_file(cluster, registries_config[registry], f"registries/{registry}/hosts.toml", create_subdir=True)

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            os_specific_associations = exe.cluster.get_associations_for_node(node.get_host(), 'containerd')
            log.debug("Uploading containerd configuration to %s node..." % node.get_node_name())
            node.put(StringIO(config_string), os_specific_associations['config_location'],
                     backup=True, sudo=True, mkdir=True)

            if config_path:
                log.debug("Uploading containerd registries configuration to %s on %s node..." %
                          (config_path, node.get_node_name()))
                node.sudo(f'mkdir -p {config_path} && sudo rm -fr {config_path}/*')
                for registry, host_config in registries_config.items():
                    node.put(StringIO(host_config), f'{config_path}/{registry}/hosts.toml',
                             backup=True, sudo=True, mkdir=True)

            log.debug("Restarting Containerd on %s node..." % node.get_node_name())
            node.sudo(
                f"chmod 600 {os_specific_associations['config_location']} && "
                f"sudo systemctl restart {os_specific_associations['service_name']} && "
                f"systemctl status {os_specific_associations['service_name']}", callback=collector)
    return collector.result


def configure(group: NodeGroup) -> RunnersGroupResult:
    configure_crictl(group)
    configure_ctr_flags(group)
    return configure_containerd(group)


def prune(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('crictl rm -fa; '
                      'sudo crictl rmp -fa; '
                      'sudo crictl rmi -a; '
                      'sudo ctr content ls -q | xargs -r sudo ctr content rm', warn=True)
