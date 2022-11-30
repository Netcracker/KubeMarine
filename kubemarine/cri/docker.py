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

import json
from io import StringIO

from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroup


def install(group: NodeGroup):
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'], 'docker')
            packages.install(node['connection'], include=os_specific_associations['package_name'])
            enable(node['connection'])

            # remove previous daemon.json to avoid problems in case when previous config was broken
            node['connection'].sudo("rm -f %s && sudo systemctl restart %s"
                                % (os_specific_associations['config_location'],
                                   os_specific_associations['service_name']))
    return exe.get_last_results_str()


def uninstall(group):
    # delete all known docker packages
    return packages.remove(group, include=['docker', 'docker-engine', 'docker.io', 'docker-ce'])


def enable(group: NodeGroup):
    # currently it is invoked only for single node
    service_name = group.cluster.get_package_association_for_node(group.get_host(), 'docker', 'service_name')
    system.enable_service(group, name=service_name, now=True)


def disable(group: NodeGroup):
    service_name = group.cluster.get_package_association_for_node(group.get_host(), 'docker', 'service_name')
    system.disable_service(group, name=service_name, now=True)


def configure(group: NodeGroup):
    log = group.cluster.log

    settings_json = json.dumps(group.cluster.inventory["services"]['cri']['dockerConfig'], sort_keys=True, indent=4)
    utils.dump_file(group.cluster, settings_json, 'docker-daemon.json')

    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'], 'docker')
            log.debug("Uploading docker configuration to %s node..." % node['name'])
            node['connection'].put(StringIO(settings_json), os_specific_associations['config_location'], backup=True,
                                   sudo=True)
            log.debug("Restarting Docker on %s node..." % node['name'])
            node['connection'].sudo(f"chmod 600 {os_specific_associations['config_location']} && "
                                    f"sudo systemctl restart {os_specific_associations['service_name']} && "
                                    f"sudo {os_specific_associations['executable_name']} info")

    return exe.get_last_results_str()


def prune(group):
    return group.sudo('docker container stop $(sudo docker container ls -aq); '
                      'sudo docker container rm $(sudo docker container ls -aq); '
                      'sudo docker system prune -a -f; '
                      # kill all containerd-shim processes, so that no orphan containers remain 
                      'sudo pkill -9 -f "^containerd-shim"', warn=True, hide=True)
