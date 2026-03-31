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

import ruamel.yaml

from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import CollectorCallback
from kubemarine import kubernetes, etcd


etcd_manifest = '/etc/kubernetes/manifests/etcd.yaml'
tmp_dir = '/etc/kubernetes/tmp/'


def reunion_member(cluster: KubernetesCluster) -> None:
    if cluster.procedure_inventory.get('corrupted_node', '') == cluster.procedure_inventory.get('healthy_node', ''):
        raise Exception('Corrupted and healthy nodes cannot be the same one')
    # Checking corrupted node
    corrupted_node = cluster.nodes['control-plane'].get_member_by_name(cluster.procedure_inventory.get('corrupted_node', ''))
    # Getting healthy etcd node
    healthy_node = cluster.nodes['control-plane'].get_member_by_name(cluster.procedure_inventory.get('healthy_node', ''))
    cluster.log.debug(f'The corrupted etcd node is: {corrupted_node.get_node_name()}. The healthy etcd node is: {healthy_node.get_node_name()}')

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


    # Checking if corrupted node is already deleted
    if member_id != '':
        cluster.log.debug(f'Corrupted member has {member_id} id, {member_ep} endpoint, and {member_peer} peer')
        result = healthy_node.sudo('etcdctl endpoint status --cluster')
        # Checking if the node is not a leader
        for member in result[healthy_node.get_host()].stdout.split("\n"):
            if len(member) > 0:
                if member_ep == member.split(", ")[0] and member.split(", ")[8] == "true":
                    raise Exception('Leader cannot be removed')
        cluster.log.debug(f'Removing corrupted member {member_id}')
        # Moving etcd.yaml to temporary folder or checking the etcd.yaml in temporary folder
        corrupted_node.sudo(f'mv --backup {etcd_manifest} {tmp_dir} || ls -1 {tmp_dir}/etcd.yaml')
        # Removing corrupted member
        healthy_node.sudo(f'etcdctl member remove {member_id}')
    else:
        cluster.log.debug(f'The {corrupted_node.get_node_name()} member must be already removed from the etcd cluster')
    # Removing erasing etcd storage
    cluster.log.debug(f'Erasing data directory')
    corrupted_node.sudo(f'rm -Rf /var/lib/etcd'
                        '&& sudo mkdir /var/lib/etcd')

    cluster.log.debug(f'Adding member')
    # Adding member into the etcd cluster
    result = healthy_node.sudo(f'etcdctl member add {corrupted_node.get_node_name()} --peer-urls={member_peer}')
    for line in result[healthy_node.get_host()].stdout.split("\n"):
        if line.startswith('ETCD_INITIAL_CLUSTER='):
            init_cluster = line.split('ETCD_INITIAL_CLUSTER=')[1]

    # Preraring etcd manifest
    collector = CollectorCallback(cluster)
    corrupted_node.sudo(f'cat {tmp_dir}/etcd.yaml', callback=collector)
    results = collector.results[corrupted_node.get_host()]
    yaml = ruamel.yaml.YAML().load(results[0].stdout)
    for command in yaml['spec']['containers'][0]['command']:
        if command.startswith('--initial-advertise-peer-urls='):
            command = f'--initial-advertise-peer-urls={member_peer}'
        if command.startswith('--initial-cluster='):
            command = f'--initial-cluster={init_cluster}'
        if command.startswith('--initial-cluster-state='):
            command = '--initial-cluster-state=existing'

    if not f'--initial-advertise-peer-urls={member_peer}' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append(f'--initial-advertise-peer-urls={member_peer}')
    if not f'--initial-advertise-peer-urls={member_peer}' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append(f'--initial-cluster={init_cluster}')
    if not '--initial-cluster-state=existing' in yaml['spec']['containers'][0]['command']:
        yaml['spec']['containers'][0]['command'].append('--initial-cluster-state=existing')

    cluster.log.debug(f'Puting etcd manifest on the corrupted node')
    buf = io.StringIO()
    ruamel.yaml.YAML().dump(yaml, buf)
    corrupted_node.put(buf, etcd_manifest, sudo=True)
    corrupted_node.sudo(f'rm {tmp_dir}/etcd.yaml', callback=collector)
    cluster.log.debug(f'Checking members list and cluster status')
    result = corrupted_node.sudo('etcdctl endpoint status --cluster')
    # Waiting for etcd pod
    _ = etcd.wait_for_health(cluster, corrupted_node)
    kubernetes.wait_for_nodes(cluster.nodes['control-plane'])
