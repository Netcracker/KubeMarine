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

import io
import json
import time
from typing import List, Dict

import fabric.connection

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup


# the methods requires etcdctl.sh to be installed on all active control-plane nodes during thirdparties task.

def remove_members(group: NodeGroup):
    log = group.cluster.log

    control_planes = group.cluster.nodes["control-plane"]
    managing_control_plane = control_planes.get_unchanged_nodes().get_any_member()

    log.verbose(f"etcd will be managed using {managing_control_plane.get_nodes_names()[0]}.")
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
    unexpected_members = etcd_members.keys() - set(control_planes.get_nodes_names())
    if unexpected_members:
        log.warning(f"Found unexpected etcd members {list(unexpected_members)}")

    for node_name in group.get_nodes_names():
        if node_name in etcd_members:
            command = "etcdctl member remove " + etcd_members[node_name]
            log.verbose(f"Removing found etcd member {node_name}...")
            managing_control_plane.sudo(command)
        else:
            log.verbose(f"Skipping {node_name} as it is not among etcd members.")


def wait_for_health(cluster: KubernetesCluster, connection: fabric.connection.Connection) -> List[Dict]:
    """
    The method checks etcd endpoints health until all endpoints are healthy or retries are exhausted
    if all member are healthy the method checks the leader.
    """
    log = cluster.log
    init_timeout = cluster.globals['etcd']['health']['init_timeout']
    timeout = cluster.globals['etcd']['health']['timeout']
    retries = cluster.globals['etcd']['health']['retries']

    is_healthy = False
    time.sleep(init_timeout)
    while retries > 0:
        start_time = time.time()
        etcd_health_raw = connection.sudo('etcdctl endpoint health --cluster -w json',
                                          is_async=False, hide=True).get_simple_out()
        end_time = time.time()
        sudo_time = int(end_time - start_time)
        log.verbose(etcd_health_raw)
        etcd_health_list = json.load(io.StringIO(etcd_health_raw.strip()))

        health = 0
        for etcd_health in etcd_health_list:
            if etcd_health.get('health'):
                health += 1

        if health == len(etcd_health_list):
            log.debug('All ETCD members are healthy!')
            is_healthy = True
            break
        else:
            log.debug('Wait for ETCD cluster is not healthy!')
            if sudo_time < timeout:
                time.sleep(timeout - sudo_time)
            retries -= 1

    if is_healthy:
        etcd_status_raw = connection.sudo('etcdctl endpoint status --cluster -w json',
                                          is_async=False, hide=True).get_simple_out()
        log.verbose(etcd_status_raw)
        etcd_status_list = json.load(io.StringIO(etcd_status_raw.lower().strip()))
        elected_leader = None
        for item in etcd_status_list:
            leader = item.get('status', {}).get('leader')
            if not leader:
                raise Exception('ETCD member "%s" do not have leader' % item.get('endpoint'))
            if not elected_leader:
                elected_leader = leader
            elif elected_leader != leader:
                raise Exception('ETCD leaders are not the same')
        log.debug('Leader "%s" elected' % elected_leader)
    else:
        raise Exception('ETCD cluster is still not healthy!')
      
    log.verbose('ETCD cluster is healthy!')

    return etcd_status_list
