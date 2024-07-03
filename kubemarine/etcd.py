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
import time
from typing import List, Dict, Optional, Tuple

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, CollectorCallback


# the methods requires etcdctl.sh to be installed on all active control-plane nodes during thirdparties task.

def remove_members(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    initial_control_planes = cluster.previous_nodes["control-plane"]
    managing_control_plane = cluster.get_unchanged_nodes().having_roles(['control-plane']).get_any_member()

    log.verbose(f"etcd will be managed using {managing_control_plane.get_node_name()}.")
    output = managing_control_plane.sudo("etcdctl member list").get_simple_out().splitlines()

    etcd_members = {}
    for line in output:
        params = [p.strip() for p in line.split(sep=',')]
        # 6 is expected number of comma-separated parameters of an etcd member
        if len(params) == 6:
            etcd_members[params[2]] = params[0]
        else:
            log.warning("Unexpected line in 'etcdctl member list' output: " + line)

    log.verbose(f"Found etcd members {list(etcd_members.keys())}")
    unexpected_members = etcd_members.keys() - set(initial_control_planes.get_nodes_names())
    if unexpected_members:
        log.warning(f"Found unexpected etcd members {list(unexpected_members)}")

    for node_name in group.get_nodes_names():
        if node_name in etcd_members:
            command = "etcdctl member remove " + etcd_members[node_name]
            log.verbose(f"Removing found etcd member {node_name}...")
            managing_control_plane.sudo(command, pty=True)
        else:
            log.verbose(f"Skipping {node_name} as it is not among etcd members.")


def wait_for_health(cluster: KubernetesCluster, node: NodeGroup) -> List[Dict]:
    """
    The method checks etcd endpoints health until all endpoints are healthy or retries are exhausted
    if all member are healthy the method checks the leader.
    """
    log = cluster.log
    timeout = cluster.globals['etcd']['health']['timeout']
    retries = cluster.globals['etcd']['health']['retries']

    is_healthy = False
    while retries > 0:
        start_time = time.time()
        is_healthy = _is_healthy(cluster, node)
        end_time = time.time()
        sudo_time = int(end_time - start_time)

        if is_healthy:
            log.debug('All ETCD members are healthy!')
            break

        log.debug('Wait for ETCD cluster is not healthy!')
        if sudo_time < timeout:
            time.sleep(timeout - sudo_time)
        retries -= 1

    if is_healthy:
        _, etcd_status_list = execute_endpoints_command(cluster, node, 'status', warn=False)
        elected_leader: Optional[int] = None
        for item in etcd_status_list:
            leader: Optional[int] = item.get('status', {}).get('leader')
            if leader is None:
                raise Exception('ETCD member "%s" do not have leader' % item.get('endpoint'))
            if elected_leader is None:
                elected_leader = leader
            elif elected_leader != leader:
                raise Exception('ETCD leaders are not the same')
        log.debug('Leader "%s" elected' % elected_leader)
    else:
        raise Exception('ETCD cluster is still not healthy!')
      
    log.verbose('ETCD cluster is healthy!')

    return etcd_status_list


def _is_healthy(cluster: KubernetesCluster, node: NodeGroup) -> bool:
    is_healthy, etcd_health_list = execute_endpoints_command(cluster, node, 'health', warn=True)
    if not is_healthy:
        return False

    health = sum(1 for etcd_health in etcd_health_list if etcd_health.get('health'))
    if health != cluster.nodes['control-plane'].nodes_amount():
        return False

    return True


def execute_endpoints_command(cluster: KubernetesCluster, node: NodeGroup, command: str,
                              *, warn: bool) -> Tuple[bool, List[dict]]:
    logger = cluster.log
    tmp_path = utils.get_remote_tmp_path()
    host = node.get_host()

    defer = node.new_defer()
    collector = CollectorCallback(cluster)

    # Separate stdout and stderr using extra temporary file
    defer.sudo(f'etcdctl endpoint {command} --cluster -w json > {tmp_path}',
               pty=True, warn=warn, callback=collector)
    defer.sudo(f'cat {tmp_path}', pty=True, warn=warn, callback=collector)
    defer.sudo(f'rm -f {tmp_path}', pty=True, warn=warn, callback=collector)

    defer.flush()
    if collector.result.is_any_failed():
        logger.verbose(collector.result)
        return False, []

    endpoints_raw = collector.results[host][1].stdout

    cluster.log.verbose(endpoints_raw)
    endpoints_list: List[dict] = json.loads(endpoints_raw.lower().rstrip('\n'))

    return True, endpoints_list
