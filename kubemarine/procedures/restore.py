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
import uuid
from collections import OrderedDict
from typing import List

import yaml

from kubemarine.core import utils, flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.resources import DynamicResources
from kubemarine.procedures import install, backup
from kubemarine import system, kubernetes, etcd


def missing_or_empty(file: str) -> bool:
    if not os.path.exists(file):
        return True
    content = utils.read_external(file)
    if re.search(r'^\s*$', content):
        return True

    return False


def replace_config_from_backup_if_needed(procedure_inventory_filepath: str, config: str) -> None:
    if missing_or_empty(config):
        print('Config is missing or empty - retrieving config from backup archive...')
        procedure = utils.load_yaml(procedure_inventory_filepath)
        if not procedure:
            procedure = {}
        backup_location = procedure.get("backup_location")
        if not backup_location:
            raise Exception('Backup location is not specified in procedure')

        print('Unpacking cluster.yaml...')
        with tarfile.open(backup_location, 'r:gz') as tar:
            member = tar.getmember('original_cluster.yaml')
            tar.makefile(member, config)
            tar.close()


def unpack_data(resources: DynamicResources) -> None:
    logger = resources.logger()
    context = resources.context
    backup_tmp_directory = backup.prepare_backup_tmpdir(logger, context)
    backup_file_source = resources.procedure_inventory().get('backup_location')

    if not backup_file_source:
        raise Exception('Backup source not specified in procedure')

    backup_file_source = utils.get_external_resource_path(backup_file_source)
    if not os.path.isfile(backup_file_source):
        raise FileNotFoundError('Backup file "%s" not found' % backup_file_source)

    logger.debug('Unpacking all data...')
    with tarfile.open(backup_file_source, 'r:gz') as tar:
        for member in tar:
            if member.isdir():
                continue
            fname = os.path.join(backup_tmp_directory, member.name)
            logger.debug(fname)
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
        context['backup_descriptor'] = yaml.safe_load(stream)


def stop_cluster(cluster: KubernetesCluster) -> None:
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


def import_nodes_data(cluster: KubernetesCluster) -> None:
    with cluster.nodes['all'].new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            node_name = node.get_node_name()
            cluster.log.debug('Uploading backup for \'%s\'' % node_name)
            node.put(os.path.join(cluster.context['backup_tmpdir'], 'nodes_data', '%s.tar.gz' % node_name),
                     '/tmp/kubemarine-backup.tar.gz')


def restore_dns_resolv_conf(cluster: KubernetesCluster) -> None:
    import_nodes_data(cluster)

    unpack_cmd = "sudo tar xzvf /tmp/kubemarine-backup.tar.gz -C / --overwrite /etc/resolv.conf"
    result = cluster.nodes['all'].sudo(
        f"readlink /etc/resolv.conf ; "
        f"if [ $? -ne 0 ]; then sudo chattr -i /etc/resolv.conf; {unpack_cmd} && sudo chattr +i /etc/resolv.conf; "
        f"fi ")

    cluster.log.debug(result)


def restore_thirdparties(cluster: KubernetesCluster) -> None:
    install.system_prepare_thirdparties(cluster)


def import_nodes(cluster: KubernetesCluster) -> None:
    if not cluster.is_task_completed('restore.dns.resolv_conf'):
        import_nodes_data(cluster)

    cluster.log.debug('Unpacking backup...')

    unpack_cmd = "sudo tar xzvf /tmp/kubemarine-backup.tar.gz -C / --overwrite --exclude /etc/resolv.conf"
    result = cluster.nodes['all'].sudo(unpack_cmd)

    cluster.log.debug(result)


def import_etcd(cluster: KubernetesCluster) -> None:
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
    for control_plane in cluster.nodes['control-plane'].get_ordered_members_configs_list():
        initial_cluster_list.append(control_plane['name'] + '=https://' + control_plane["internal_address"] + ":2380")
        initial_cluster_list_without_names.append(control_plane["internal_address"] + ":2379")
    initial_cluster = ','.join(initial_cluster_list)

    if "docker" == cluster.inventory['services']['cri']['containerRuntime']:
        cont_runtime = "docker"
    else:
        cont_runtime = "ctr"
    container_name = f'etcd-{uuid.uuid4().hex}'
    network_options = '--network host' if cont_runtime == 'docker' else '--net-host'
    mount_options = '-v /var/lib/etcd:/var/lib/etcd ' \
                    '-v /etc/kubernetes/pki:/etc/kubernetes/pki ' \
        if cont_runtime == 'docker' else \
        '-mount type=bind,src=/var/lib/etcd,dst=/var/lib/etcd,options=rbind:rw ' \
        '-mount type=bind,src=/etc/kubernetes/pki/etcd,dst=/etc/kubernetes/pki/etcd,options=rbind:rw'
    name_option = f'--name {container_name}' if cont_runtime == 'docker' else ''
    container_id = '' if cont_runtime == 'docker' else f'{container_name}'

    etcd_instances = 0
    for control_plane in cluster.nodes['control-plane'].get_ordered_members_configs_list():
        cluster.log.debug('Restoring ETCD member ' + control_plane['name'])
        control_plane_conn = cluster.make_group([control_plane['connect_to']])
        control_plane_conn.sudo(
            f'chmod 777 {snap_name} && '
            f'sudo ls -la {snap_name} && '
            f'sudo etcdctl snapshot restore {snap_name} '
            f'--name={control_plane["name"]} '
            f'--data-dir=/var/lib/etcd/snapshot '
            f'--initial-cluster={initial_cluster} '
            f'--initial-advertise-peer-urls=https://{control_plane["internal_address"]}:2380',
            hide=False)

        _ = control_plane_conn.sudo(
            f'mv /var/lib/etcd/snapshot/member /var/lib/etcd/member && '
            f'sudo rm -rf /var/lib/etcd/snapshot {snap_name} && '
            f'sudo {cont_runtime} run -d {network_options} '
            f'--env ETCDCTL_API=3 {name_option} '
            f'{mount_options} '
            f'{etcd_image} {container_id} etcd '
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
            f'--peer-trusted-ca-file={etcd_peer_cacert} ').get_simple_out().strip()

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

    # Stop and remove container
    if cont_runtime == 'docker':
        cluster.nodes['control-plane'].sudo(f"docker stop {container_name} && "
                                            f"sudo docker rm {container_name}")
    else:
        cluster.nodes['control-plane'].sudo(f"ctr task rm -f {container_name} && "
                                            f"sudo ctr container rm {container_name}")


def reboot(cluster: KubernetesCluster) -> None:
    system.reboot_group(cluster.nodes['all'], try_graceful=False)
    kubernetes.wait_for_nodes(cluster.nodes['control-plane'])


tasks = OrderedDict({
    "prepare": {
        "stop_cluster": stop_cluster,
    },
    "restore": {
        "dns": {
            "resolv_conf": restore_dns_resolv_conf,
        },
        "thirdparties": restore_thirdparties,
    },
    "import": {
        "nodes": import_nodes,
        "etcd": import_etcd
    },
    "reboot": reboot
})


class RestoreFlow(flow.Flow):
    def _run(self, resources: DynamicResources) -> None:
        unpack_data(resources)
        flow.run_actions(resources, [RestoreAction()])


class RestoreAction(Action):
    def __init__(self) -> None:
        super().__init__('restore', recreate_inventory=True)

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)
        res.make_final_inventory()


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for restoring Kubernetes resources and nodes contents from backup file.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='restore')
    context['backup_descriptor'] = {}

    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    args = context['execution_arguments']

    replace_config_from_backup_if_needed(args['procedure_config'], args['config'])

    RestoreFlow().run_flow(context)


if __name__ == '__main__':
    main()
