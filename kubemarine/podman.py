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

from distutils.util import strtobool
from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.executor import RemoteExecutor


def install(group):
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return "Podman could not be installed with docker"

    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'])['podman']

            group.cluster.log.debug("Installing latest podman on %s node" % node['name'])
            # always install latest available podman
            packages.install(node['connection'], include=os_specific_associations['package_name'])

            # remove previous config.toml to avoid problems in case when previous config was broken
            node['connection'].sudo("rm -f %s && sudo systemctl restart %s"
                                    % (os_specific_associations['config_location'],
                                       os_specific_associations['service_name']))

            system.enable_service(node['connection'], os_specific_associations['service_name'], now=True)
    return exe.get_last_results_str()


def configure(group):
    cri_impl = group.cluster.inventory['services']['cri']['containerRuntime']

    if cri_impl == "docker":
        return "Podman could not be installed with docker"

    log = group.cluster.log

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
    if config_toml.get('plugins', {}).get('io.containerd.grpc.v1.cri', {}).get('registry', {}).get('mirrors'):
        for mirror, mirror_conf in config_toml['plugins']['io.containerd.grpc.v1.cri']['registry']['mirrors'].items():
            is_insecure = False
            for endpoint in mirror_conf.get('endpoint', []):
                if "http://" in endpoint:
                    is_insecure = True
                    break
            if is_insecure:
                insecure_registries.append(mirror)

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
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'])['podman']
            log.debug("Restarting podman on %s node..." % node['name'])
            node['connection'].sudo(f"sudo systemctl restart {os_specific_associations['service_name']} && "
                                    f"systemctl status {os_specific_associations['service_name']}")
    return exe.get_last_results_str()
