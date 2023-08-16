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
import base64

from distutils.util import strtobool
from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback


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


def convert_toml_dict_to_str(config: dict) -> str:
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
    return config_string


def configure_ctr_flags(group: NodeGroup) -> None:
    cluster = group.cluster
    log = cluster.log
    containerd_config = cluster.inventory["services"]["cri"]['containerdConfig']
    config_string = convert_toml_dict_to_str(containerd_config)
    config_toml = toml.loads(config_string)

    # Calculate ctr options for image pull
    registry = config_toml.get('plugins', {}).get('io.containerd.grpc.v1.cri', {}).get('registry', {})
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

    # Save ctr pull options
    log.debug("Uploading ctr flags configuration...")
    group.put(StringIO(ctr_pull_options_str), "/etc/ctr/kubemarine_ctr_flags.conf", backup=True, sudo=True, mkdir=True)
    group.sudo("chmod 600 /etc/ctr/kubemarine_ctr_flags.conf")


def configure(group: NodeGroup) -> RunnersGroupResult:
    cluster = group.cluster
    log = cluster.log

    log.debug("Uploading crictl configuration for containerd...")
    crictl_config = yaml.dump({"runtime-endpoint": "unix:///run/containerd/containerd.sock"})
    utils.dump_file(cluster, crictl_config, 'crictl.yaml')
    group.put(StringIO(crictl_config), '/etc/crictl.yaml', backup=True, sudo=True)

    configure_ctr_flags(group)

    config_string = convert_toml_dict_to_str(cluster.inventory["services"]["cri"]['containerdConfig'])
    utils.dump_file(cluster, config_string, 'containerd-config.toml')
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            os_specific_associations = exe.cluster.get_associations_for_node(node.get_host(), 'containerd')
            log.debug("Uploading containerd configuration to %s node..." % node.get_node_name())
            node.put(StringIO(config_string), os_specific_associations['config_location'],
                     backup=True, sudo=True, mkdir=True)
            log.debug("Restarting Containerd on %s node..." % node.get_node_name())
            node.sudo(
                f"chmod 600 {os_specific_associations['config_location']} && "
                f"sudo systemctl restart {os_specific_associations['service_name']} && "
                f"systemctl status {os_specific_associations['service_name']}", callback=collector)
    return collector.result


def prune(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('crictl rm -fa; '
                      'sudo crictl rmp -fa; '
                      'sudo crictl rmi -a; '
                      'sudo ctr content ls -q | xargs -r sudo ctr content rm', warn=True)
