# Copyright 2021-2026 NetCracker Technology Corporation
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

from typing import List

import ruamel.yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import CollectorCallback
from kubemarine import kubernetes, etcd


etcd_manifest = '/etc/kubernetes/manifests/etcd.yaml'
tmp_dir = '/etc/kubernetes/tmp/'


def reunion_member(cluster: KubernetesCluster) -> None:
    if cluster.procedure_inventory.get('corrupted_node', '') == cluster.procedure_inventory.get('healthy_node', ''):
        raise Exception('Corrupted and healthy nodes must be different')
    # Checking corrupted node
    corrupted_node = cluster.nodes['control-plane'].get_member_by_name(cluster.procedure_inventory.get('corrupted_node', ''))
    # Getting healthy etcd node
    healthy_node = cluster.nodes['control-plane'].get_member_by_name(cluster.procedure_inventory.get('healthy_node', ''))
    cluster.log.debug(f'The corrupted etcd node is: "{corrupted_node.get_node_name()}". '
                      f'The healthy etcd node is: "{healthy_node.get_node_name()}"')

    cluster.log.debug(f'Checking members list')
    member_id = ''
    member_ep = ''
    member_peer = ''
    result = healthy_node.sudo('etcdctl member list')
    # Getting member ID
    for member in result[healthy_node.get_host()].stdout.split("\n"):
        if len(member) > 0:
            if member.split(", ")[2] == corrupted_node.get_node_name():
                member_id = member.split(", ")[0]
                member_ep = member.split(", ")[4]
                member_peer = member.split(", ")[3]

    if not member_id:
        raise Exception('The corrupted member cannot be identified')
    else:
        cluster.log.debug(f'Corrupted member has ID: "{member_id}"; Endpoint: "{member_ep}"; Peer: "{member_peer}"')
    cluster.log.debug(f'Removing corrupted member {member_id}')
    # Moving etcd.yaml to temporary folder
    corrupted_node.sudo(f'mkdir -p {tmp_dir}'
                        f'&& sudo mv {etcd_manifest} {tmp_dir}')
    # Checking if etcd container has been deleted
    corrupted_node.sudo('crictl rm -f $(sudo crictl ps --name etcd -q) || true > /dev/null')
    # Removing corrupted member
    healthy_node.sudo(f'etcdctl member remove {member_id}')
    # Erasing etcd storage
    cluster.log.debug(f'Erasing data directory')
    corrupted_node.sudo(f'rm -Rf /var/lib/etcd'
                        '&& sudo mkdir /var/lib/etcd')

    cluster.log.debug(f'Adding member')
    # Adding member into the etcd cluster
    result = healthy_node.sudo(f'etcdctl member add {corrupted_node.get_node_name()} --peer-urls={member_peer}')
    for line in result[healthy_node.get_host()].stdout.split("\n"):
        if line.startswith('ETCD_INITIAL_CLUSTER='):
            init_cluster = line.split('ETCD_INITIAL_CLUSTER=')[1].replace('"','')

    # Preraring etcd manifest
    collector = CollectorCallback(cluster)
    corrupted_node.sudo(f'cat {tmp_dir}/etcd.yaml', callback=collector)
    results = collector.results[corrupted_node.get_host()]
    yaml = ruamel.yaml.YAML().load(results[0].stdout)
    commands: List[str] = yaml['spec']['containers'][0]['command']
    for i, command in enumerate(commands):
        if command.startswith('--initial-advertise-peer-urls='):
            commands[i] = f'--initial-advertise-peer-urls={member_peer}'
        if command.startswith('--initial-cluster='):
            commands[i] = f'--initial-cluster={init_cluster}'
        if command.startswith('--initial-cluster-state='):
            commands[i] = '--initial-cluster-state=existing'

    if not f'--initial-advertise-peer-urls={member_peer}' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append(f'--initial-advertise-peer-urls={member_peer}')
    if not f'--initial-cluster={init_cluster}' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append(f'--initial-cluster={init_cluster}')
    if not '--initial-cluster-state=existing' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append('--initial-cluster-state=existing')

    cluster.log.debug(f'Putting etcd manifest on the corrupted node')
    buf = io.StringIO()
    ruamel.yaml.YAML().dump(yaml, buf)
    corrupted_node.put(buf, etcd_manifest, sudo=True)
    corrupted_node.sudo(f'rm {tmp_dir}/etcd.yaml', callback=collector)
    cluster.log.debug(f'Checking members list and cluster status')
    # Waiting for etcd pod
    etcd.wait_for_health(cluster, corrupted_node)
    kubernetes.wait_for_nodes(cluster.nodes['control-plane'])
