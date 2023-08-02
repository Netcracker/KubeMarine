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
import shutil
import tarfile
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import List, Tuple, Union, Dict, Literal, Optional, Iterator

import yaml

from kubemarine.core import utils, flow, log
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup
from kubemarine.core.resources import DynamicResources


def get_default_backup_files_list(cluster: KubernetesCluster) -> List[str]:
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
        "/root/.kube/config",
        "/etc/systemd/system/kubelet.service"
    ]

    cri_impl = cluster.inventory['services']['cri']['containerRuntime']
    if cri_impl == "docker":
        backup_files_list.append("/etc/docker/daemon.json")
    elif cri_impl == "containerd":
        backup_files_list.append("/etc/containerd/config.toml")
        backup_files_list.append("/etc/crictl.yaml")

    return backup_files_list


def prepare_backup_tmpdir(cluster: KubernetesCluster) -> str:
    backup_directory = cluster.context.get('backup_tmpdir')
    if not backup_directory:
        cluster.log.verbose('Backup directory is not ready yet, preparing..')
        backup_directory = cluster.context['backup_tmpdir'] = utils.get_dump_filepath(cluster.context, 'backup')
        shutil.rmtree(backup_directory, ignore_errors=True)
        os.mkdir(backup_directory)
        cluster.log.verbose('Backup directory prepared')
    return backup_directory


def verify_backup_location(cluster: KubernetesCluster) -> None:
    target = utils.get_external_resource_path(cluster.procedure_inventory.get('backup_location', 'backup.tar.gz'))
    if not os.path.isdir(target) and not os.path.isdir(os.path.abspath(os.path.join(target, os.pardir))):
        raise FileNotFoundError('Backup location directory not exists')


def export_ansible_inventory(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster)
    shutil.copyfile(cluster.context['execution_arguments']['ansible_inventory_location'],
                    os.path.join(backup_directory, 'ansible-inventory.ini'))
    cluster.log.verbose('ansible-inventory.ini exported to backup')


def export_packages_list(cluster: KubernetesCluster) -> None:
    cluster.context['backup_descriptor']['nodes']['packages'] = {}
    if cluster.get_os_family() in ['rhel', 'rhel8']:
        cmd = r"rpm -qa"
    else:
        cmd = r"dpkg-query -f '${Package}=${Version}\n' -W"
    results = cluster.nodes['all'].sudo(cmd)
    for host, result in results.items():
        cluster.context['backup_descriptor']['nodes']['packages'][host] = result.stdout.strip().split('\n')


def export_hostname(cluster: KubernetesCluster) -> None:
    cluster.context['backup_descriptor']['nodes']['hostnames'] = {}
    results = cluster.nodes['all'].sudo('hostnamectl status | head -n 1 | sed -e \'s/[a-zA-Z ]*://g\'')
    cluster.log.verbose(results)
    for host, result in results.items():
        cluster.context['backup_descriptor']['nodes']['hostnames'][host] = result.stdout.strip()


def export_cluster_yaml(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster)
    shutil.copyfile(utils.get_dump_filepath(cluster.context, 'cluster.yaml'),
                    os.path.join(backup_directory, 'cluster.yaml'))
    shutil.copyfile(utils.get_external_resource_path(cluster.context['execution_arguments']['config']),
                    os.path.join(backup_directory, 'original_cluster.yaml'))
    cluster.log.verbose('cluster.yaml exported to backup')


def export_nodes(cluster: KubernetesCluster) -> None:
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
    for node in cluster.nodes['all'].get_ordered_members_list():
        node.get('/tmp/kubemarine-backup.tar.gz',
                 os.path.join(backup_nodes_data_dir, '%s.tar.gz' % node.get_node_name()))
        cluster.log.debug('Backup \'%s\' downloaded' % node.get_node_name())

    cluster.log.verbose('Deleting backup file from nodes...')
    cluster.nodes['all'].sudo('rm -f /tmp/kubemarine-backup.tar.gz')


def export_etcd(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster)
    etcd_node, is_custom_etcd_node = select_etcd_node(cluster)
    cluster.context['backup_descriptor']['etcd']['image'] = retrieve_etcd_image(cluster, etcd_node)

    # Try to detect cluster health and other metadata like db size, leader
    etcd_status = None
    try:
        status_json = etcd_node.sudo('etcdctl endpoint status --cluster -w json').get_simple_out()
        cluster.log.verbose(status_json)

        etcd_status = json.load(io.StringIO(status_json.lower()))
        parsed_etcd_status = {}
        for item in etcd_status:
            # get rid of https:// and :2379
            address = item['endpoint'].split('//')[1].split(':')[0]
            node_name = cluster.nodes['all'].get_first_member(apply_filter={"internal_address": address}).get_node_name()
            parsed_etcd_status[node_name] = item
        cluster.context['backup_descriptor']['etcd']['status'] = parsed_etcd_status
    except Exception:
        cluster.log.verbose('Failed to load and parse ETCD status')

    if is_custom_etcd_node:
        cluster.context['backup_descriptor']['etcd']['source'] = etcd_node.get_node_name()
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
    endpoint_ip = etcd_node.get_config()["internal_address"]
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


def select_etcd_node(cluster: KubernetesCluster) -> Tuple[NodeGroup, bool]:
    custom_etcd_node = cluster.procedure_inventory.get('backup_plan', {}).get('etcd', {}).get('source_node')

    if custom_etcd_node:
        if not cluster.nodes['all'].has_node(custom_etcd_node):
            raise Exception('Unknown ETCD node selected as source')
        etcd_node = cluster.nodes['all'].get_member_by_name(custom_etcd_node)
        return etcd_node, True
    else:
        return cluster.nodes['control-plane'].get_any_member(), False


def retrieve_etcd_image(cluster: KubernetesCluster, etcd_node: NodeGroup) -> str:
    # TODO: Detect ETCD version via /etc/kubernetes/manifests/etcd.yaml config if presented, otherwise use containers
    node_name = etcd_node.get_node_name()
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
                return f"{image['repoTags'][0]}"

    raise Exception("Unable to find etcd image on node %s" % node_name)


def export_kubernetes_version(cluster: KubernetesCluster) -> None:
    control_plane = cluster.nodes['control-plane'].get_any_member()
    version = control_plane.sudo('kubectl get nodes --no-headers | head -n 1 | awk \'{print $5; exit}\'').get_simple_out()
    cluster.context['backup_descriptor']['kubernetes']['version'] = version.strip()


def _load_namespaces(logger: log.EnhancedLogger, control_plane: NodeGroup) -> List[Dict[str, str]]:
    namespaces_result = control_plane.sudo(
        'kubectl get ns -o jsonpath=\'{range .items[*]}{.metadata.name}{"\\n"}{end}\'')
    logger.verbose(namespaces_result)
    parsed_namespaces = namespaces_result.get_simple_out().strip().split('\n')
    return [{'name': name} for name in parsed_namespaces]


def _load_resources(logger: log.EnhancedLogger, control_plane: NodeGroup, namespaced: bool) -> List[Dict[str, str]]:
    resources_result = control_plane.sudo(f'kubectl api-resources --verbs=list --sort-by=name '
                                          f'--namespaced{"" if namespaced else "=false"}')
    logger.verbose(resources_result)
    resources_table = utils.parse_aligned_table(resources_result.get_simple_out())

    resources = [
        {
            'name': _resolve_full_resource_name(row['NAME'], row['APIVERSION']),
            'kind': row['KIND'],
        }
        for row in resources_table
    ]

    return [r for r in resources if r['name'] not in ('events.events.k8s.io', 'events')]


def _resolve_full_resource_name(name: str, apiversion: str) -> str:
    if '/' not in apiversion:
        return name

    return name + '.' + apiversion[0:apiversion.rindex('/')]


def _filter_resources_by_proposed(logger: log.EnhancedLogger,
                                  loaded_resources: List[Dict[str, str]],
                                  proposed_resources: Union[List[str], Literal['all']],
                                  kind: str) -> List[Dict[str, str]]:
    resources = []
    for resource in loaded_resources:
        name = resource['name']
        if proposed_resources == 'all' or name in proposed_resources:
            resources.append(resource)
        else:
            logger.verbose(f'{kind.capitalize()} "{name}" excluded')

    if proposed_resources != 'all':
        for proposed_resource in proposed_resources:
            if not any(proposed_resource == resource['name'] for resource in resources):
                raise Exception(f'Proposed {kind} "{proposed_resource}" not found in loaded cluster {kind}s')

    logger.debug([r['name'] for r in resources])
    return resources


class ParserPayload:
    def __init__(self, event: str, resource_path: str, namespace: Optional[str]):
        self.event = event
        self.resource_path = resource_path
        self.namespace = namespace


class ExportKubernetesParser:
    def __init__(self,
                 logger: log.EnhancedLogger,
                 backup_directory: str,
                 namespaced_resources: List[Dict[str, str]],
                 nonnamespaced_resources: List[Dict[str, str]]):
        self.logger = logger
        self.backup_directory = backup_directory
        self.namespaced_resources = namespaced_resources
        self.nonnamespaced_resources = nonnamespaced_resources
        self.namespaced_resources_result_map: Dict[str, List[str]] = {}
        self.nonnamespaced_resources_result: List[str] = []
        self.closed = False
        self.elapsed: float = 0
        self.total_files = 0
        self._task_queue: 'Queue[ParserPayload]' = Queue()
        self._yaml_transformer = utils.yaml_structure_preserver()
        self._parsing_started = False
        self._prev_namespace: Optional[str] = None

    def schedule(self, task: ParserPayload) -> None:
        self._task_queue.put(task)

    def close(self) -> None:
        self.closed = True

    def unprocessed(self) -> List[ParserPayload]:
        if not self.closed:
            raise Exception("Parser is still processing the resources")

        return list(self._task_queue.queue)

    def run(self) -> None:
        while True:
            task = self._task_queue.get()
            if task.event == 'end':
                return

            start = time.time()
            self._handle(task)
            os.remove(task.resource_path)
            self.elapsed += (time.time() - start)

    def _handle(self, task: ParserPayload) -> None:
        namespace = task.namespace
        if not self._parsing_started or namespace != self._prev_namespace:
            if namespace:
                self.logger.debug(f"Loading resources from namespace {namespace!r}...")
            else:
                self.logger.debug(f"Loading non-namespaced resources...")

            self._prev_namespace = namespace

        self._parsing_started = True

        resource_path = task.resource_path
        if namespace:
            self.logger.verbose(f"Parsing resources for namespace {namespace!r} from file {resource_path}...")
        else:
            self.logger.verbose(f"Parsing non-namespaced resources from file {resource_path}...")

        with utils.open_utf8(resource_path) as file:
            template = self._yaml_transformer.load(file)

        if template is None:
            # No resources found and the file is empty.
            return

        items = template.pop('items')
        resources = self.nonnamespaced_resources if namespace is None else self.namespaced_resources
        items_by_resource: Dict[str, List[dict]] = {}
        for item in items:
            resource_name = next(r['name'] for r in resources if r['kind'] == item['kind'])
            items_by_resource.setdefault(resource_name, []).append(item)

        for resource in resources:
            resource_name = resource['name']
            items = items_by_resource.get(resource_name)
            if items is None:
                continue

            resource_list = dict(template)
            resource_list['items'] = items

            location = os.path.join(self.backup_directory, 'kubernetes_resources')
            if namespace is not None:
                location = os.path.join(location, namespace)

            os.makedirs(location, exist_ok=True)

            resource_file_path = os.path.join(location, '%s.yaml' % resource_name)
            self.logger.verbose(
                f"Dumping list of resource {resource_name!r}"
                f"{'' if namespace is None else (' for namespace ' + repr(namespace))}...")
            with utils.open_utf8(resource_file_path, 'w') as file:
                self._yaml_transformer.dump(resource_list, file)

            if namespace is None:
                self.nonnamespaced_resources_result.append(resource_name)
            else:
                self.namespaced_resources_result_map.setdefault(namespace, []).append(resource_name)

            self.total_files += 1


class ExportKubernetesDownloader:
    def __init__(self,
                 backup_directory: str,
                 control_plane: NodeGroup,
                 parser: ExportKubernetesParser,
                 namespaces: List[Dict[str, str]],
                 namespaced_resources: List[Dict[str, str]],
                 nonnamespaced_resources: List[Dict[str, str]],
                 ):
        self.backup_directory = backup_directory
        self.control_plane = control_plane
        self.parser = parser
        self.namespaces = namespaces
        self.namespaced_resources = namespaced_resources
        self.nonnamespaced_resources = nonnamespaced_resources
        self.elapsed: float = 0

    @staticmethod
    def _split(resources: List[Dict[str, str]]) -> List[List[str]]:
        # Split resource types by chunks to reduce memory consumption.
        chunk_size = 10
        return [[r['name'] for r in resources[i:(i + chunk_size)]]
                for i in range(0, len(resources), chunk_size)]

    def _tasks(self) -> Iterator[Tuple[Optional[str], List[str]]]:
        for resources in self._split(self.nonnamespaced_resources):
            yield None, resources

        for namespace in self.namespaces:
            for resources in self._split(self.namespaced_resources):
                yield namespace['name'], resources

    def run(self) -> None:
        start = time.time()
        try:
            for namespace, resources in self._tasks():
                if self.parser.closed:
                    # No need to continue as the parser is already closed due to error.
                    # Remove unprocessed local temp files.
                    for payload in self.parser.unprocessed():
                        os.remove(payload.resource_path)
                    return

                temp_local_filepath = os.path.join(self.backup_directory, uuid.uuid4().hex)

                cmd = f'kubectl{"" if namespace is None else (" -n " + namespace)} get --ignore-not-found ' \
                      f'{",".join(r for r in resources)} ' \
                      f'-o yaml'

                # There is no way to parallel resources connection via Queue or Pool:
                # the ssh connection is not possible to parallelize due to thread lock.
                # Though it is still potentially possible to use few connections or few control-plane nodes.
                with utils.open_utf8(temp_local_filepath, 'w') as out:
                    self.control_plane.sudo(cmd, out_stream=out)

                self.parser.schedule(ParserPayload("do", temp_local_filepath, namespace))
        finally:
            self.parser.schedule(ParserPayload("end", "", None))
            self.elapsed = time.time() - start


def export_kubernetes(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster)
    control_plane = cluster.nodes['control-plane'].get_any_member()
    backup_kubernetes = cluster.procedure_inventory.get('backup_plan', {}).get('kubernetes', {})
    logger = cluster.log

    logger.debug('Loading namespaces:')
    loaded_namespaces = _load_namespaces(logger, control_plane)
    proposed_namespaces = backup_kubernetes.get('namespaced_resources', {}).get('namespaces', 'all')
    namespaces = _filter_resources_by_proposed(logger, loaded_namespaces, proposed_namespaces, 'namespace')

    logger.debug('Loading namespaced resource types:')
    loaded_resources = _load_resources(logger, control_plane, True)
    proposed_resources = backup_kubernetes.get('namespaced_resources', {}).get('resources', 'all')
    namespaced_resources = _filter_resources_by_proposed(logger, loaded_resources, proposed_resources, 'resource')

    logger.debug('Loading non-namespaced resource types:')
    loaded_resources = _load_resources(logger, control_plane, False)
    proposed_resources = backup_kubernetes.get('nonnamespaced_resources', 'all')
    nonnamespaced_resources = _filter_resources_by_proposed(logger, loaded_resources, proposed_resources, 'resource')

    logger.debug('Loading resources:')
    start = time.time()

    # Split loading of resources into downloading (mostly IO) and parsing (mostly CPU).
    #
    # Processing of the particular resource includes
    #   * downloading of the `kubectl` result
    #   * parsing and splitting it into files.
    #
    # Only after that the processing is considered as finished.
    # Thus, only parser outputs the progress.
    parser = ExportKubernetesParser(logger, backup_directory, namespaced_resources, nonnamespaced_resources)
    downloader = ExportKubernetesDownloader(backup_directory, control_plane, parser,
                                            namespaces, namespaced_resources, nonnamespaced_resources)

    with ThreadPoolExecutor(max_workers=2) as tpe:
        downloader_async = tpe.submit(downloader.run)
        parser_async = tpe.submit(parser.run)

        try:
            # Wait for successful parsing of resources or till exception.
            parser_async.result()
            parser.close()
        except BaseException:
            parser.close()
            try:
                # Wait for graceful exiting of downloader after currently running command is finished.
                downloader_async.result()
            except BaseException as e:
                # If both background tasks fail, the parser exception has priority, and the other is logged.
                logger.verbose(e)

            # Parser exception has priority because it happens for the earlier chunk of resources.
            raise

        # Although parser may exit successfully, not all resources might be processed due to error in downloader.
        downloader_async.result()

    downloaded_resources_descriptor = cluster.context['backup_descriptor']['kubernetes']['resources']
    if parser.namespaced_resources_result_map:
        downloaded_resources_descriptor['namespaced'] = parser.namespaced_resources_result_map

    if parser.nonnamespaced_resources_result:
        downloaded_resources_descriptor['nonnamespaced'] = parser.nonnamespaced_resources_result

    logger.verbose(f'Downloading elapsed: {downloader.elapsed}')
    logger.verbose(f'Parsing elapsed: {parser.elapsed}')
    logger.verbose(f'Total elapsed: {time.time() - start}')
    logger.verbose(f'Total files saved: {parser.total_files}')


def make_descriptor(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster)

    cluster.context['backup_descriptor']['kubernetes']['thirdparties'] = cluster.inventory['services']['thirdparties']
    cluster.context['backup_descriptor']['meta']['time']['finished'] = datetime.datetime.now()

    with utils.open_external(os.path.join(backup_directory, 'descriptor.yaml'), 'w') as output:
        output.write(yaml.dump(cluster.context['backup_descriptor']))


def pack_data(cluster: KubernetesCluster) -> None:
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
    def __init__(self) -> None:
        super().__init__('backup')

    def run(self, res: DynamicResources) -> None:
        flow.run_tasks(res, tasks)


def main(cli_arguments: List[str] = None) -> None:
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

    flow.ActionsFlow([BackupAction()]).run_flow(context)


if __name__ == '__main__':
    main()
