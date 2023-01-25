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

from io import StringIO

import toml
import yaml
import json

from distutils.util import strtobool
from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup


def install(group: NodeGroup):
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'], 'containerd')

            group.cluster.log.debug("Installing latest containerd and podman on %s node" % node['name'])
            # always install latest available containerd and podman
            packages.install(node['connection'], include=os_specific_associations['package_name'])

            # remove previous config.toml to avoid problems in case when previous config was broken
            node['connection'].sudo("rm -f %s && sudo systemctl restart %s"
                                    % (os_specific_associations['config_location'],
                                       os_specific_associations['service_name']))

            system.enable_service(node['connection'], os_specific_associations['service_name'], now=True)
    return exe.get_last_results_str()


def configure(group: NodeGroup):
    log = group.cluster.log

    log.debug("Uploading crictl configuration for containerd...")
    crictl_config = yaml.dump({"runtime-endpoint": "unix:///run/containerd/containerd.sock"})
    utils.dump_file(group.cluster, crictl_config, 'crictl.yaml')
    group.put(StringIO(crictl_config), '/etc/crictl.yaml', backup=True, sudo=True)

    config_string = ""
    # double loop is used to make sure that no "simple" `key: value` pairs are accidentally assigned to sections
    containerd_config = group.cluster.inventory["services"]["cri"]['containerdConfig']
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

    # if there are any insecure registries in containerd config, then it is required to configure them for podman too
    config_toml = toml.loads(config_string)
    insecure_registries = []
    registry = config_toml.get('plugins', {}).get('io.containerd.grpc.v1.cri', {}).get('registry', {})
    if registry.get('mirrors'):
        for mirror, mirror_conf in registry['mirrors'].items():
            is_insecure = registry.get('configs', {}).get(mirror, {}).get('tls', {}).get('insecure_skip_verify', False)
            for endpoint in mirror_conf.get('endpoint', []):
                if "http://" in endpoint:
                    is_insecure = True
                    break
            if is_insecure:
                insecure_registries.append(mirror)
    # save 'auth.json' if there are credentials for registry
    auth_registries = {"auths": {}}
    if registry.get('configs'):
        registry_configs = registry['configs']
        for auth_registry in registry_configs:
            auth_registries['auths'][auth_registry] = {}
            if registry_configs[auth_registry].get('auth', {}).get('auth', ''):
                auth_registries['auths'][auth_registry]['auth'] = registry_configs[auth_registry]['auth']['auth']
        auth_json = json.dumps(auth_registries)
        group.put(StringIO(auth_json), "/etc/containers/auth.json", backup=True, sudo=True)
        group.sudo("chmod 600 /etc/containers/auth.json")
    if insecure_registries:
        log.debug("Uploading podman configuration...")
        podman_registries = f"[registries.insecure]\nregistries = {insecure_registries}\n"
        utils.dump_file(group.cluster, podman_registries, 'podman_registries.conf')
        group.sudo("mkdir -p /etc/containers/")
        group.put(StringIO(podman_registries), "/etc/containers/registries.conf", backup=True, sudo=True)
    else:
        log.debug("Removing old podman configuration...")
        group.sudo("rm -f /etc/containers/registries.conf")

    utils.dump_file(group.cluster, config_string, 'containerd-config.toml')
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'], 'containerd')
            log.debug("Uploading containerd configuration to %s node..." % node['name'])
            node['connection'].put(StringIO(config_string), os_specific_associations['config_location'], backup=True,
                                   sudo=True, mkdir=True)
            log.debug("Restarting Containerd on %s node..." % node['name'])
            node['connection'].sudo(f"chmod 600 {os_specific_associations['config_location']} && "
                                    f"sudo systemctl restart {os_specific_associations['service_name']} && "
                                    f"systemctl status {os_specific_associations['service_name']}")
    return exe.get_last_results_str()


def prune(group):
    return group.sudo('crictl rm -fa; '
                      'sudo crictl rmp -fa; '
                      'sudo crictl rmi -a; '
                      'sudo ctr content ls -q | xargs -r sudo ctr content rm', warn=True)
