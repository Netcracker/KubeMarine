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
from kubemarine.core.group import NodeGroup, RunnersGroupResult, CollectorCallback


def install(group: NodeGroup) -> RunnersGroupResult:
    cluster = group.cluster
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            os_specific_associations = cluster.get_associations_for_node(node.get_host(), 'docker')
            packages.install(node, include=os_specific_associations['package_name'], callback=collector)

            system.enable_service(node, name=os_specific_associations['service_name'],
                                  now=True, callback=collector)

            # remove previous daemon.json to avoid problems in case when previous config was broken
            node.sudo("rm -f %s && sudo systemctl restart %s"
                      % (os_specific_associations['config_location'],
                         os_specific_associations['service_name']),
                      callback=collector)
    return collector.result


def uninstall(group: NodeGroup) -> RunnersGroupResult:
    # delete all known docker packages
    return packages.remove(group, include=['docker', 'docker-engine', 'docker.io', 'docker-ce'])


def disable(group: NodeGroup) -> None:
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = exe.cluster.get_package_association_for_node(
                node.get_host(), 'docker', 'service_name')
            system.disable_service(node, name=service_name, now=True)


def configure(group: NodeGroup) -> RunnersGroupResult:
    cluster = group.cluster
    log = cluster.log

    settings_json = json.dumps(cluster.inventory["services"]['cri']['dockerConfig'], sort_keys=True, indent=4)
    utils.dump_file(cluster, settings_json, 'docker-daemon.json')

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            os_specific_associations = exe.cluster.get_associations_for_node(node.get_host(), 'docker')
            log.debug("Uploading docker configuration to %s node..." % node.get_node_name())
            node.put(StringIO(settings_json), os_specific_associations['config_location'],
                     backup=True, sudo=True)
            log.debug("Restarting Docker on %s node..." % node.get_node_name())
            node.sudo(
                f"chmod 600 {os_specific_associations['config_location']} && "
                f"sudo systemctl restart {os_specific_associations['service_name']} && "
                f"sudo {os_specific_associations['executable_name']} info",
                callback=collector)

    return collector.result


def prune(group: NodeGroup) -> RunnersGroupResult:
    return group.sudo('docker container stop $(sudo docker container ls -aq); '
                      'sudo docker container rm $(sudo docker container ls -aq); '
                      'sudo docker system prune -a -f; '
                      # kill all containerd-shim processes, so that no orphan containers remain 
                      'sudo pkill -9 -f "^containerd-shim"', warn=True)
