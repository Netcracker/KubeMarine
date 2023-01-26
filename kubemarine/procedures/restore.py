#!/usr/bin/env python3
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


import os
import re
import tarfile
import time
from collections import OrderedDict
import yaml

from kubemarine.core import utils, flow, defaults
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install, backup
from kubemarine import system, kubernetes, etcd


def missing_or_empty(file):
    if not os.path.exists(file):
        return True
    content = utils.read_external(file)
    if re.search(r'^\s*$', content):
        return True


def replace_config_from_backup_if_needed(procedure_inventory_filepath, config):
    if missing_or_empty(config):
        print('Config is missing or empty - retrieving config from backup archive...')
        with utils.open_external(procedure_inventory_filepath, 'r') as stream:
            procedure = yaml.safe_load(stream)
        backup_location = procedure.get("backup_location")
        if not backup_location:
            raise Exception('Backup location is not specified in procedure')

        print('Unpacking cluster.yaml...')
        with tarfile.open(backup_location, 'r:gz') as tar:
            member = tar.getmember('original_cluster.yaml')
            tar.makefile(member, config)
            tar.close()


def unpack_data(cluster):
    backup_tmp_directory = backup.prepare_backup_tmpdir(cluster)
    backup_file_source = cluster.procedure_inventory.get('backup_location')

    if not backup_file_source:
        raise Exception('Backup source not specified in procedure')

    backup_file_source = utils.get_external_resource_path(backup_file_source)
    if not os.path.isfile(backup_file_source):
        raise FileNotFoundError('Backup file "%s" not found' % backup_file_source)

    cluster.log.debug('Unpacking all data...')
    with tarfile.open(backup_file_source, 'r:gz') as tar:
        for member in tar:
            if member.isdir():
                continue
            fname = os.path.join(backup_tmp_directory, member.name)
            cluster.log.debug(fname)
            fname_parts = fname.split('/')
            if len(fname_parts) > 1:
                fname_dir = "/".join(fname_parts[:-1])
                if not os.path.isdir(fname_dir):
                    os.makedirs(fname_dir, exist_ok=True)
            tar.makefile(member, fname)
        tar.close()

    descriptor_filepath = os.path.join(backup_tmp_directory, 'descriptor.yaml')
    if not os.path.isfile(descriptor_filepath):
        raise FileNotFoundError('Descriptor not found in backup file')

    with utils.open_external(descriptor_filepath, 'r') as stream:
        cluster.context['backup_descriptor'] = yaml.safe_load(stream)


def verify_backup_data(cluster):
    if not cluster.context['backup_descriptor'].get('kubernetes', {}).get('version'):
        cluster.log.debug('Not possible to verify Kubernetes version, because descriptor do not contain such information')
        return

    if cluster.context['backup_descriptor']['kubernetes']['version'] != cluster.inventory['services']['kubeadm']['kubernetesVersion']:
        cluster.log.warning('Installed kubernetes versions do not match version from backup')
        cluster.log.verbose('Cluster re-parse required')
        if not cluster.raw_inventory.get('services'):
            cluster.raw_inventory['services'] = {}
        if not cluster.raw_inventory['services'].get('kubeadm'):
            cluster.raw_inventory['services']['kubeadm'] = {}
        cluster.raw_inventory['services']['kubeadm']['kubernetesVersion'] = cluster.context['backup_descriptor']['kubernetes']['version']
        cluster._inventory = defaults.enrich_inventory(cluster, cluster.raw_inventory)
    else:
        cluster.log.debug('Kubernetes version from backup is correct')


def stop_cluster(cluster):
    cluster.log.debug('Stopping the existing cluster...')
    cri_impl = cluster.inventory['services']['cri']['containerRuntime']
    if cri_impl == "docker":
        result = cluster.nodes['control-plane'].sudo('systemctl stop kubelet; '
                                              'sudo docker kill $(sudo docker ps -q); '
                                              'sudo docker rm -f $(sudo docker ps -a -q); '
                                              'sudo docker ps -a; '
                                              'sudo rm -rf /var/lib/etcd; '
                                              'sudo mkdir -p /var/lib/etcd', warn=True)
    else:
        result = cluster.nodes['control-plane'].sudo('systemctl stop kubelet; '
                                              'sudo crictl rm -fa; '
                                              'sudo crictl ps -a; '
                                              'sudo rm -rf /var/lib/etcd; '
                                              'sudo mkdir -p /var/lib/etcd', warn=True)
    cluster.log.verbose(result)


def restore_thirdparties(cluster):
    custom_thirdparties = cluster.procedure_inventory.get('restore_plan', {}).get('thirdparties', {})
    if custom_thirdparties:
        for name, value in custom_thirdparties.items():
            cluster.inventory['services']['thirdparties'][name]['source'] = value['source']
            if value.get('sha1'):
                cluster.inventory['services']['thirdparties'][name]['sha1'] = value['sha1']

    install.system_prepare_thirdparties(cluster)


def import_nodes(cluster):
    for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
        node['connection'].put(os.path.join(cluster.context['backup_tmpdir'], 'nodes_data', '%s.tar.gz' % node['name']),
                               '/tmp/kubemarine-backup.tar.gz')
        cluster.log.debug('Backup \'%s\' uploaded' % node['name'])

    cluster.log.debug('Unpacking backup...')
    result = cluster.nodes['all'].sudo(
        'chattr -i /etc/resolv.conf; sudo tar xzvf /tmp/kubemarine-backup.tar.gz -C / --overwrite && sudo chattr +i /etc/resolv.conf')
    cluster.log.debug(result)


def import_etcd(cluster: KubernetesCluster):
    etcd_all_certificates = cluster.procedure_inventory.get('restore_plan', {}).get('etcd', {}).get('certificates', {})
    etcd_cert = etcd_all_certificates.get('cert', cluster.globals['etcd']['default_arguments']['cert'])
    etcd_key = etcd_all_certificates.get('key', cluster.globals['etcd']['default_arguments']['key'])
    etcd_cacert = etcd_all_certificates.get('cacert', cluster.globals['etcd']['default_arguments']['cacert'])
    etcd_peer_cert = etcd_all_certificates.get('peer_cert', cluster.globals['etcd']['default_arguments']['peer_cert'])
    etcd_peer_key = etcd_all_certificates.get('peer_key', cluster.globals['etcd']['default_arguments']['peer_key'])
    etcd_peer_cacert = etcd_all_certificates.get('peer_cacert',
                                                 cluster.globals['etcd']['default_arguments']['peer_cacert'])

    etcd_image = cluster.procedure_inventory.get('restore_plan', {}).get('etcd', {}).get('image')
    if not etcd_image:
        etcd_image = cluster.context['backup_descriptor'].get('etcd', {}).get('image')
    if not etcd_image:
        raise Exception('Unknown ETCD image to restore from')
    cluster.log.verbose('ETCD will be restored from the following image: ' + etcd_image)

    cluster.log.debug('Uploading ETCD snapshot...')
    snap_name = '/var/lib/etcd/etcd-snapshot%s.db' % int(round(time.time() * 1000))
    cluster.nodes['control-plane'].put(os.path.join(cluster.context['backup_tmpdir'], 'etcd.db'), snap_name, sudo=True)

    initial_cluster_list = []
    initial_cluster_list_without_names = []
    for control_plane in cluster.nodes['control-plane'].get_ordered_members_list(provide_node_configs=True):
        initial_cluster_list.append(control_plane['name'] + '=https://' + control_plane["internal_address"] + ":2380")
        initial_cluster_list_without_names.append(control_plane["internal_address"] + ":2379")
    initial_cluster = ','.join(initial_cluster_list)

    if "docker" == cluster.inventory['services']['cri']['containerRuntime']:
        cont_runtime = "docker"
    else:
        cont_runtime = "podman"

    etcd_instances = 0
    for control_plane in cluster.nodes['control-plane'].get_ordered_members_list(provide_node_configs=True):
        cluster.log.debug('Restoring ETCD member ' + control_plane['name'])
        control_plane_conn: NodeGroup = control_plane['connection']
        control_plane_conn.sudo(
            f'chmod 777 {snap_name} && '
            f'sudo ls -la {snap_name} && '
            f'sudo etcdctl snapshot restore {snap_name} '
            f'--name={control_plane["name"]} '
            f'--data-dir=/var/lib/etcd/snapshot '
            f'--initial-cluster={initial_cluster} '
            f'--initial-advertise-peer-urls=https://{control_plane["internal_address"]}:2380',
            hide=False)

        etcd_id = control_plane_conn.sudo(
            f'mv /var/lib/etcd/snapshot/member /var/lib/etcd/member && '
            f'sudo rm -rf /var/lib/etcd/snapshot {snap_name} && '
            f'sudo {cont_runtime} run -d --network host -p 2379:2379 -p 2380:2380 '
            f'-e ETCDCTL_API=3 '
            f'-v /var/lib/etcd:/var/lib/etcd '
            f'-v /etc/kubernetes/pki:/etc/kubernetes/pki '
            f'{etcd_image} etcd '
            f'--advertise-client-urls=https://{control_plane["internal_address"]}:2379 '
            f'--cert-file={etcd_cert} '
            f'--key-file={etcd_key} '
            f'--trusted-ca-file={etcd_cacert} '
            f'--client-cert-auth=true '
            f'--data-dir=/var/lib/etcd '
            f'--initial-advertise-peer-urls=https://{control_plane["internal_address"]}:2380 '
            f'--initial-cluster={initial_cluster} '
            f'--listen-client-urls=https://127.0.0.1:2379,https://{control_plane["internal_address"]}:2379 '
            f'--listen-peer-urls=https://{control_plane["internal_address"]}:2380 '
            f'--name={control_plane["name"]} '
            f'--peer-client-cert-auth=true '
            f'--peer-cert-file={etcd_peer_cert} '
            f'--peer-key-file={etcd_peer_key} '
            f'--peer-trusted-ca-file={etcd_peer_cacert} '
        ).get_simple_out().strip()

        control_plane_conn.sudo(f'{cont_runtime} logs {etcd_id}', hide=False)
        etcd_instances += 1

    # After restore check db size equal, cluster health and leader elected
    # Checks should be changed
    cluster_status = etcd.wait_for_health(cluster, cluster.nodes['control-plane'].get_any_member())

    # Check DB size is correct
    backup_source = cluster.context['backup_descriptor'].get('etcd', {}).get('source')
    etcd_statuses_from_descriptor = cluster.context['backup_descriptor'].get('etcd', {}).get('status', {})
    if backup_source and etcd_statuses_from_descriptor and etcd_statuses_from_descriptor.get(backup_source, {}).get('status', {}).get('dbsize'):
        expected_dbsize = int(etcd_statuses_from_descriptor.get(backup_source, {}).get('status', {}).get('dbsize'))
        for item in cluster_status:
            real_dbsize = int(item.get('status', {}).get('dbsize'))
            if not real_dbsize:
                raise Exception('ETCD member "%s" do not have DB size' % item.get('endpoint'))
            cluster.log.verbose('Endpoint "%s" DB real size %s, expected size %s' % (item.get('endpoint'), expected_dbsize, real_dbsize))
            # restored db should have equal or greater DB size
            if expected_dbsize > real_dbsize:
                raise Exception('ETCD member "%s" has invalid DB size' % item.get('endpoint'))
        cluster.log.debug('DB size "%s" is correct' % expected_dbsize)
    else:
        cluster.log.verbose('It is not possible to verify db size - descriptor do not contain such information')


def reboot(cluster):
    system.reboot_group(cluster.nodes['all'], try_graceful=False)
    kubernetes.wait_for_nodes(cluster.nodes['control-plane'])


tasks = OrderedDict({
    "prepare": {
        "unpack": unpack_data,
        "verify_backup_data": verify_backup_data,
        "stop_cluster": stop_cluster,
    },
    "restore": {
        "thirdparties": restore_thirdparties,
    },
    "import": {
        "nodes": import_nodes,
        "etcd": import_etcd
    },
    "reboot": reboot
})


class RestoreAction(Action):
    def __init__(self):
        super().__init__('restore')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for restoring Kubernetes resources and nodes contents from backup file.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='restore')
    args = context['execution_arguments']

    replace_config_from_backup_if_needed(args['procedure_config'], args['config'])

    flow.run_actions(context, [RestoreAction()])


if __name__ == '__main__':
    main()
