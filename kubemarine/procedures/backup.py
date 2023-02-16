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


import datetime
import io
import json
import os
import random
import shutil
import tarfile
import time
from collections import OrderedDict
import yaml

from kubemarine.core import utils, flow
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources


def get_default_backup_files_list(cluster: KubernetesCluster):
    haproxy_service = cluster.get_package_association('haproxy', 'service_name')
    keepalived_service = cluster.get_package_association('keepalived', 'service_name')

    backup_files_list = [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/chrony.conf",
        "/etc/selinux/config",
        "/etc/yum.repos.d/",
        "/var/lib/kubelet/pki",
        "/etc/modules-load.d/",
        "/etc/audit/rules.d/",
        "/etc/haproxy/haproxy.cfg",
        f"/etc/systemd/system/{haproxy_service}.service.d/{haproxy_service}.conf",
        "/etc/keepalived/keepalived.conf",
        f"/etc/systemd/system/{keepalived_service}.service.d/{keepalived_service}.conf",
        "/usr/local/bin/check_haproxy.sh",
        "/etc/kubernetes",
        "/etc/systemd/system/kubelet.service"
    ]

    cri_impl = cluster.inventory['services']['cri']['containerRuntime']
    if cri_impl == "docker":
        backup_files_list.append("/etc/docker/daemon.json")
    elif cri_impl == "containerd":
        backup_files_list.append("/etc/containerd/config.toml")
        backup_files_list.append("/etc/crictl.yaml")

    return backup_files_list


def prepare_backup_tmpdir(cluster):
    backup_directory = cluster.context.get('backup_tmpdir')
    if not backup_directory:
        cluster.log.verbose('Backup directory is not ready yet, preparing..')
        backup_directory = cluster.context['backup_tmpdir'] = utils.get_dump_filepath(cluster.context, 'backup')
        shutil.rmtree(backup_directory, ignore_errors=True)
        os.mkdir(backup_directory)
        cluster.log.verbose('Backup directory prepared')
    return backup_directory


def verify_backup_location(cluster):
    target = utils.get_external_resource_path(cluster.procedure_inventory.get('backup_location', 'backup.tar.gz'))
    if not os.path.isdir(target) and not os.path.isdir(os.path.abspath(os.path.join(target, os.pardir))):
        raise FileNotFoundError('Backup location directory not exists')


def export_ansible_inventory(cluster):
    backup_directory = prepare_backup_tmpdir(cluster)
    shutil.copyfile(cluster.context['execution_arguments']['ansible_inventory_location'],
                    os.path.join(backup_directory, 'ansible-inventory.ini'))
    cluster.log.verbose('ansible-inventory.ini exported to backup')


def export_packages_list(cluster: KubernetesCluster):
    cluster.context['backup_descriptor']['nodes']['packages'] = {}
    if cluster.get_os_family() in ['rhel', 'rhel8']:
        cmd = r"rpm -qa"
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W"
    results = cluster.nodes['all'].sudo(cmd)
    for conn, result in results.items():
        cluster.context['backup_descriptor']['nodes']['packages'][conn.host] = result.stdout.strip().split('\n')


def export_hostname(cluster):
    cluster.context['backup_descriptor']['nodes']['hostnames'] = {}
    results = cluster.nodes['all'].sudo('hostnamectl status | head -n 1 | sed -e \'s/[a-zA-Z ]*://g\'')
    cluster.log.verbose(results)
    for conn, result in results.items():
        cluster.context['backup_descriptor']['nodes']['hostnames'][conn.host] = result.stdout.strip()


def export_cluster_yaml(cluster):
    backup_directory = prepare_backup_tmpdir(cluster)
    shutil.copyfile(utils.get_dump_filepath(cluster.context, 'cluster.yaml'),
                    os.path.join(backup_directory, 'cluster.yaml'))
    shutil.copyfile(utils.get_external_resource_path(cluster.context['execution_arguments']['config']),
                    os.path.join(backup_directory, 'original_cluster.yaml'))
    cluster.log.verbose('cluster.yaml exported to backup')


def export_nodes(cluster):
    backup_directory = prepare_backup_tmpdir(cluster)
    backup_nodes_data_dir = os.path.join(backup_directory, 'nodes_data')
    os.mkdir(backup_nodes_data_dir)

    backup_list = get_default_backup_files_list(cluster)
    for filepath, enabled in cluster.procedure_inventory.get('backup_plan', {}).get('nodes', {}).items():
        if not enabled and filepath in backup_list:
            backup_list.remove(filepath)
        if enabled and filepath not in backup_list:
            backup_list.append(filepath)

    cluster.log.debug('Backing up the following files: \n' + '  - ' + '\n  - '.join(backup_list))

    backup_command = 'cd /tmp && ' \
                     'sudo tar -czvf /tmp/kubemarine-backup.tar.gz -P $(sudo readlink -e %s) && ' \
                     'sudo ls -la /tmp/kubemarine-backup.tar.gz && ' \
                     'sudo du -hs /tmp/kubemarine-backup.tar.gz' % (' '.join(backup_list))

    data_copy_res = cluster.nodes['all'].run(backup_command)

    cluster.log.debug('Backup created:\n%s' % data_copy_res)

    cluster.log.debug('Downloading nodes backups:')
    for node in cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True):
        node['connection'].get('/tmp/kubemarine-backup.tar.gz',
                               os.path.join(backup_nodes_data_dir, '%s.tar.gz' % node['name']))
        cluster.log.debug('Backup \'%s\' downloaded' % node['name'])

    cluster.log.verbose('Deleting backup file from nodes...')
    cluster.nodes['all'].sudo('rm -f /tmp/kubemarine-backup.tar.gz')


def export_etcd(cluster: KubernetesCluster):
    backup_directory = prepare_backup_tmpdir(cluster)
    etcd_node, is_custom_etcd_node = select_etcd_node(cluster)
    cluster.context['backup_descriptor']['etcd']['image'] = retrieve_etcd_image(cluster, etcd_node)

    # Try to detect cluster health and other metadata like db size, leader
    etcd_status = None
    try:
        result = etcd_node.sudo('etcdctl endpoint status --cluster -w json').get_simple_out()
        cluster.log.verbose(result)

        etcd_status = json.load(io.StringIO(result.lower()))
        parsed_etcd_status = {}
        for item in etcd_status:
            # get rid of https:// and :2379
            address = item['endpoint'].split('//')[1].split(':')[0]
            node_name = cluster.nodes['all'].get_first_member(apply_filter={"internal_address": address}, provide_node_configs=True)['name']
            parsed_etcd_status[node_name] = item
        cluster.context['backup_descriptor']['etcd']['status'] = parsed_etcd_status
    except Exception:
        cluster.log.verbose('Failed to load and parse ETCD status')

    if is_custom_etcd_node:
        cluster.context['backup_descriptor']['etcd']['source'] = etcd_node.get_nodes_names()[0]
    else:
        # if user did not provide node, then we have to select leader by ourselves
        if not etcd_status:
            raise Exception('Failed to load ETCD status and impossible to detect ETCD leader for making snapshot from it')
        etcd_leader_id = etcd_status[0]['status']['leader']
        etcd_leader_name = None
        for name, item in parsed_etcd_status.items():
            if item['status']['header']['member_id'] == etcd_leader_id:
                etcd_leader_name = name
        if etcd_leader_name:
            cluster.log.verbose('Detected ETCD leader: %s' % etcd_leader_name)
            cluster.context['backup_descriptor']['etcd']['source'] = etcd_leader_name
            etcd_node = cluster.nodes['control-plane'].get_member_by_name(etcd_leader_name)
        else:
            raise Exception('Failed to detect ETCD leader - not possible to create backup from actual DB')

    snap_name = 'snapshot%s.db' % int(round(time.time() * 1000))
    endpoint_ip = etcd_node.get_ordered_members_list(provide_node_configs=True)[0]["internal_address"]
    cluster.log.debug('Creating ETCD backup "%s"...' % snap_name)
    result = etcd_node.sudo(f'etcdctl snapshot save /var/lib/etcd/{snap_name} --endpoints=https://{endpoint_ip}:2379 '
                            f'&& sudo mv /var/lib/etcd/{snap_name} /tmp/{snap_name} '
                            f'&& sudo ls -la /tmp/{snap_name} '
                            f'&& sudo du -hs /tmp/{snap_name} '
                            f'&& sudo chmod 666 /tmp/{snap_name}', timeout=600)
    cluster.log.debug(result)
    etcd_node.get('/tmp/' + snap_name, backup_directory + '/etcd.db')
    cluster.log.verbose('Deleting ETCD snapshot file from "%s"...')
    etcd_node.sudo('rm -f /tmp/%s' % snap_name)


def select_etcd_node(cluster):
    custom_etcd_node = cluster.procedure_inventory.get('backup_plan', {}).get('etcd', {}).get('source_node')

    if custom_etcd_node:
        etcd_node = cluster.nodes['all'].get_member_by_name(custom_etcd_node)
        if etcd_node is None:
            raise Exception('Unknown ETCD node selected as source')
        return etcd_node, True
    else:
        return cluster.nodes['control-plane'].get_any_member(), False


def retrieve_etcd_image(cluster, etcd_node):
    # TODO: Detect ETCD version via /etc/kubernetes/manifests/etcd.yaml config if presented, otherwise use containers
    node_name = etcd_node.get_nodes_names()[0]
    if "docker" == cluster.inventory['services']['cri']['containerRuntime']:
        cont_inspect = "docker inspect $(sudo docker ps -a | grep etcd-%s | awk '{print $1; exit}')" % node_name
        etcd_container_json = json.loads(list(etcd_node.sudo(cont_inspect).values())[0].stdout)[0]
        etcd_image_sha = etcd_container_json['Image'][7:]  # remove "sha256:" prefix

        images_result = etcd_node.sudo("docker image ls --format '{{json .}}'")
        formatted_images_result = "[" + ",".join(list(images_result.values())[0].stdout.strip().split('\n')) + "]"
        images_json = json.loads(formatted_images_result)
        for image in images_json:
            if image['ID'] == etcd_image_sha[:len(image['ID'])]:
                return f"{image['Repository']}:{image['Tag']}"
    else:
        cont_search = "sudo crictl ps --label io.kubernetes.pod.name=etcd-%s -aq | awk '{print $1; exit}'" % node_name
        cont_inspect = f"crictl inspect $({cont_search})"
        etcd_container_json = json.loads(list(etcd_node.sudo(cont_inspect).values())[0].stdout)
        etcd_image_sha = etcd_container_json['info']['config']['image']['image']

        images_json = json.loads(list(etcd_node.sudo("crictl images -v -o json").values())[0].stdout)['images']
        for image in images_json:
            if image['id'] == etcd_image_sha:
                return image['repoTags'][0]

    raise Exception("Unable to find etcd image on node %s" % node_name)


def export_kubernetes_version(cluster: KubernetesCluster):
    control_plane = cluster.nodes['control-plane'].get_any_member()
    version = control_plane.sudo('kubectl get nodes --no-headers | head -n 1 | awk \'{print $5; exit}\'').get_simple_out()
    cluster.context['backup_descriptor']['kubernetes']['version'] = version.strip()


# There is no way to parallel resources connection via Queue or Pool:
# the ssh connection is not possible to parallelize due to thread lock
def download_resources(log, resources, location, control_plane: NodeGroup, namespace=None):

    if namespace:
        log.debug('Downloading resources from namespace "%s"...' % namespace)

    actual_resources = []

    if not resources:
        log.debug('No resources found to download')
        return actual_resources

    cmd = ''
    resource_separator = ''.join(random.choice('=-_') for _ in range(32))

    for resource in resources:
        if cmd != '':
            cmd += ' && echo \'\n' + resource_separator + '\n\' && '
        if namespace:
            cmd += 'sudo kubectl -n %s get --ignore-not-found %s -o yaml' % (namespace, resource)
        else:
            cmd += 'sudo kubectl get --ignore-not-found %s -o yaml' % resource

    result = control_plane.sudo(cmd).get_simple_out()
    control_plane.cluster.log.verbose(result)

    found_resources_results = result.split(resource_separator)
    for i, result in enumerate(found_resources_results):
        resource = resources[i]
        resource_file_path = os.path.join(location, '%s.yaml' % resource)
        result = result.strip()
        if result and result != '':
            actual_resources.append(resource)
            with utils.open_external(resource_file_path, 'w') as resource_file_stream:
                resource_file_stream.write(result)

    return actual_resources


def export_kubernetes(cluster):
    backup_directory = prepare_backup_tmpdir(cluster)
    control_plane = cluster.nodes['control-plane'].get_any_member()

    cluster.log.debug('Loading namespaces:')
    namespaces_result = control_plane.sudo('kubectl get ns -o yaml')
    cluster.log.verbose(namespaces_result)
    namespaces_string = list(namespaces_result.values())[0].stdout.strip()
    namespaces_yaml = yaml.safe_load(namespaces_string)

    proposed_namespaces = cluster.procedure_inventory.get('backup_plan', {}).get('kubernetes', {}).get('namespaced_resources', {}).get('namespaces', 'all')
    namespaces = []
    for item in namespaces_yaml['items']:
        name = item['metadata']['name']
        if proposed_namespaces == 'all' or name in proposed_namespaces:
            cluster.log.verbose('Namespace "%s" added' % name)
            namespaces.append(name)
        else:
            cluster.log.verbose('Namespace "%s" excluded' % name)

    if proposed_namespaces != 'all':
        for proposed_namespace in proposed_namespaces:
            if proposed_namespace not in namespaces:
                raise Exception('Proposed namespace "%s" not found in loaded cluster namespaces' % proposed_namespace)

    cluster.log.debug(namespaces)
    kubernetes_res_dir = os.path.join(backup_directory, 'kubernetes_resources')
    os.mkdir(kubernetes_res_dir)

    cluster.log.debug('Loading namespaced resources:')
    resources_result = control_plane.sudo('kubectl api-resources --verbs=list --namespaced -o name '
                                   '| grep -v "events.events.k8s.io" | grep -v "events" | sort | uniq')
    cluster.log.verbose(resources_result)
    parsed_resources = list(resources_result.values())[0].stdout.strip().split('\n')
    proposed_resources = cluster.procedure_inventory.get('backup_plan', {}).get('kubernetes', {}).get('namespaced_resources', {}).get('resources', 'all')

    resources = [resource for resource in parsed_resources if proposed_resources == 'all' or resource in proposed_resources]

    for resource in parsed_resources:
        if resource not in resources:
            cluster.log.verbose('Resource "%s" excluded' % resource)

    if proposed_resources != 'all':
        for proposed_resource in proposed_resources:
            if proposed_resource not in resources:
                raise Exception('Proposed resource "%s" not found in loaded cluster resources' % proposed_resource)

    cluster.log.debug(resources)

    namespaced_resources_map = {}
    total_files = 0

    for namespace in namespaces:
        namespace_dir = os.path.join(kubernetes_res_dir, namespace)
        os.mkdir(namespace_dir)
        actual_resources = download_resources(cluster.log, resources, namespace_dir, control_plane, namespace)
        if actual_resources:
            total_files += len(actual_resources)
            namespaced_resources_map[namespace] = actual_resources

    cluster.log.debug('Loading non-namespaced resources:')
    resources_result = control_plane.sudo('kubectl api-resources --verbs=list --namespaced=false -o name '
                                   '| grep -v "events.events.k8s.io" | grep -v "events" | sort | uniq')
    cluster.log.verbose(resources_result)
    parsed_resources = list(resources_result.values())[0].stdout.strip().split('\n')
    proposed_resources = cluster.procedure_inventory.get('backup_plan', {}).get('kubernetes', {}).get('nonnamespaced_resources', 'all')

    resources = [resource for resource in parsed_resources if proposed_resources == 'all' or resource in proposed_resources]

    for resource in parsed_resources:
        if resource not in resources:
            cluster.log.verbose('Resource "%s" excluded' % resource)

    if proposed_resources != 'all':
        for proposed_resource in proposed_resources:
            if proposed_resource not in resources:
                raise Exception('Proposed resource "%s" not found in loaded cluster resources' % proposed_resource)

    cluster.log.debug(resources)

    nonnamespaced_resources_list = download_resources(cluster.log, resources, kubernetes_res_dir, control_plane)
    total_files += len(nonnamespaced_resources_list)

    cluster.log.verbose('Total files saved: %s' % total_files)

    if namespaced_resources_map:
        cluster.context['backup_descriptor']['kubernetes']['resources']['namespaced'] = namespaced_resources_map

    if nonnamespaced_resources_list:
        cluster.context['backup_descriptor']['kubernetes']['resources']['nonnamespaced'] = nonnamespaced_resources_list


def make_descriptor(cluster):
    backup_directory = prepare_backup_tmpdir(cluster)

    cluster.context['backup_descriptor']['kubernetes']['thirdparties'] = cluster.inventory['services']['thirdparties']
    cluster.context['backup_descriptor']['meta']['time']['finished'] = datetime.datetime.now()

    with utils.open_external(os.path.join(backup_directory, 'descriptor.yaml'), 'w') as output:
        output.write(yaml.dump(cluster.context['backup_descriptor']))


def pack_data(cluster):
    cluster_name = cluster.inventory['cluster_name']
    backup_directory = prepare_backup_tmpdir(cluster)

    backup_filename = 'backup-%s-%s.tar.gz' % (cluster_name, utils.get_current_timestamp_formatted())

    target = utils.get_external_resource_path(cluster.procedure_inventory.get('backup_location', backup_filename))
    if os.path.isdir(target):
        target = os.path.join(target, backup_filename)

    cluster.log.debug('Packing all data...')
    with tarfile.open(target, "w:gz") as tar_handle:
        for root, dirs, files in os.walk(backup_directory):
            for file in files:
                pathname = os.path.join(root, file)
                tar_handle.add(pathname, pathname.replace(backup_directory, ''))
        tar_handle.close()

    cluster.log.verbose('Cleaning up...')
    shutil.rmtree(backup_directory, ignore_errors=True)


tasks = OrderedDict({
    "verify_backup_location": verify_backup_location,
    "export": {
        "inventory": {
            "cluster_yaml": export_cluster_yaml,
            "ansible_inventory": export_ansible_inventory,
        },
        "lists": {
            "rpms": export_packages_list,
            "hostname": export_hostname,
        },
        "nodes": export_nodes,
        "etcd": export_etcd,
        "cluster_version": export_kubernetes_version,
        "kubernetes": export_kubernetes,
    },
    "make_descriptor": make_descriptor,
    "pack": pack_data,
})


class BackupAction(Action):
    def __init__(self):
        super().__init__('backup')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for making backup of Kubernetes resources and nodes contents.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks)

    context = flow.create_context(parser, cli_arguments, procedure='backup')
    context['execution_arguments']['disable_dump'] = False
    context['backup_descriptor'] = {
        'meta': {
            'time': {
                'started': datetime.datetime.now()
            }
        },
        'etcd': {},
        'nodes': {},
        'kubernetes': {
            'resources': {}
        }
    }

    flow.run_actions(context, [BackupAction()])


if __name__ == '__main__':
    main()
