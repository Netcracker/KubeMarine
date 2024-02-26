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
import gzip
import io
import json
import os
import shutil
import tarfile
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from typing import List, Tuple, Union, Dict, Optional, Iterator
from typing_extensions import Literal

import yaml

from kubemarine.core import utils, flow, log
from kubemarine.core.action import Action
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, RemoteExecutor
from kubemarine.core.resources import DynamicResources
from kubemarine.cri import containerd


def get_default_backup_files_list(cluster: KubernetesCluster) -> List[str]:
    haproxy_service = cluster.get_package_association('haproxy', 'service_name')
    keepalived_service = cluster.get_package_association('keepalived', 'service_name')

    backup_files_list = [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/chrony.conf",
        "/etc/selinux/config",
        "/etc/yum.repos.d/",
        "/etc/apt/sources.list.d/",
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
        backup_files_list.append("/etc/ctr/kubemarine_ctr_flags.conf")
        config_path = containerd.get_config_path(cluster.inventory)
        if config_path:
            backup_files_list.append(config_path)


    return backup_files_list


def prepare_backup_tmpdir(logger: log.EnhancedLogger, context: dict) -> str:
    backup_directory = context.get('backup_tmpdir')
    if not backup_directory:
        logger.verbose('Backup directory is not ready yet, preparing..')
        backup_directory = context['backup_tmpdir'] = utils.get_dump_filepath(context, 'backup')
        shutil.rmtree(backup_directory, ignore_errors=True)
        os.mkdir(backup_directory)
        logger.verbose('Backup directory prepared')
    return backup_directory


def verify_backup_location(cluster: KubernetesCluster) -> None:
    target = utils.get_external_resource_path(cluster.procedure_inventory.get('backup_location', 'backup.tar.gz'))
    if not os.path.isdir(target) and not os.path.isdir(os.path.abspath(os.path.join(target, os.pardir))):
        raise FileNotFoundError('Backup location directory not exists')


def export_ansible_inventory(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)
    shutil.copyfile(cluster.context['execution_arguments']['ansible_inventory_location'],
                    os.path.join(backup_directory, 'ansible-inventory.ini'))
    cluster.log.verbose('ansible-inventory.ini exported to backup')


def export_packages_list(cluster: KubernetesCluster) -> None:
    cluster.context['backup_descriptor']['nodes']['packages'] = {}
    if cluster.get_os_family() in ['rhel', 'rhel8', 'rhel9']:
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
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)
    shutil.copyfile(utils.get_dump_filepath(cluster.context, 'cluster.yaml'),
                    os.path.join(backup_directory, 'cluster.yaml'))
    shutil.copyfile(utils.get_external_resource_path(cluster.context['execution_arguments']['config']),
                    os.path.join(backup_directory, 'original_cluster.yaml'))
    cluster.log.verbose('cluster.yaml exported to backup')


def export_nodes(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)
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
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)
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
            'apiVersion': row['APIVERSION'],
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
                 nonnamespaced_resources: List[Dict[str, str]],
                 graceful_finish_barrier: int,
                 ):
        self.logger = logger
        self.backup_directory = backup_directory
        self.namespaced_resources = namespaced_resources
        self.nonnamespaced_resources = nonnamespaced_resources
        self.namespaced_resources_result_map: Dict[str, List[str]] = {}
        self.nonnamespaced_resources_result: List[str] = []
        self.closed = False
        self.elapsed: float = 0
        self.total_files = 0
        self._graceful_finish_barrier = graceful_finish_barrier
        self._task_queue: 'Queue[ParserPayload]' = Queue()
        self._lock = threading.Lock()

    def schedule(self, payload: ParserPayload) -> None:
        with self._lock:
            if not self.closed:
                self._task_queue.put(payload)
            else:
                self._clear(payload)

    def finish(self, graceful: bool) -> None:
        with self._lock:
            self._graceful_finish_barrier -= 1
            if not self.closed and (self._graceful_finish_barrier == 0 or not graceful):
                self._task_queue.put(ParserPayload("end", "", None))
                self._graceful_finish_barrier = 0

    def run(self) -> None:
        try:
            while True:
                payload = self._task_queue.get()
                if payload.event == 'end':
                    return

                start = time.time()
                self._handle(payload)
                # do not clear the currently processing payload in case of exception
                self._clear(payload)
                self.elapsed += (time.time() - start)
        finally:
            with self._lock:
                self.closed = True
                # Queue might be not empty in case of exception. Need to clear all pending payloads
                for payload in self._task_queue.queue:
                    self._clear(payload)

    @staticmethod
    def _clear(payload: ParserPayload) -> None:
        if payload.event == 'do':
            os.remove(payload.resource_path)

    def _parse_identity(self, line: str, api_version: str, kind: str) -> Tuple[str, str]:
        if kind == '':
            kind = self._parse_single_line_property(line, 'kind')
        if api_version == '':
            api_version = self._parse_single_line_property(line, 'apiVersion')

        return api_version, kind

    @staticmethod
    def _parse_single_line_property(line: str, key: str) -> str:
        item_prop = line[2:]
        val = ''
        if item_prop.startswith(f'{key}:'):
            val = yaml.safe_load(item_prop)[key]

        return val

    def _handle(self, payload: ParserPayload) -> None:
        namespace = payload.namespace
        if namespace:
            self.logger.debug(f"Loading resources from namespace {namespace!r}...")
        else:
            self.logger.debug(f"Loading non-namespaced resources...")

        resources = self.nonnamespaced_resources if namespace is None else self.namespaced_resources
        items_by_resource: Dict[str, List[str]] = {}

        def append_item(api_version: str, kind: str, item: str) -> None:
            resource_name = next(r['name'] for r in resources if r['apiVersion'] == api_version and r['kind'] == kind)
            items_by_resource.setdefault(resource_name, []).append(item)

        with gzip.open(payload.resource_path, 'rt', encoding='utf-8') as file:
            header = ''
            remainder = ''
            item = ''
            api_version, kind = '', ''
            stage = 'header'
            for line in file:
                if stage == 'header':
                    if line.startswith('- '):
                        stage = 'items'
                        item = line
                        api_version, kind = self._parse_identity(line, '', '')
                    else:
                        header += line
                elif stage == 'items':
                    if line.startswith('- '):
                        append_item(api_version, kind, item)
                        item = line
                        api_version, kind = self._parse_identity(line, '', '')
                    elif not line[0].isspace():
                        stage = 'remainder'
                        append_item(api_version, kind, item)
                        remainder = line
                    else:
                        item += line
                        api_version, kind = self._parse_identity(line, api_version, kind)
                elif stage == 'remainder':
                    remainder += line

        for resource in resources:
            resource_name = resource['name']
            items = items_by_resource.get(resource_name)
            if items is None:
                continue

            location = os.path.join(self.backup_directory, 'kubernetes_resources')
            if namespace is not None:
                location = os.path.join(location, namespace)

            os.makedirs(location, exist_ok=True)

            resource_file_path = os.path.join(location, '%s.yaml' % resource_name)
            self.logger.verbose(
                f"Dumping list of resource {resource_name!r}"
                f"{'' if namespace is None else (' for namespace ' + repr(namespace))}...")
            with utils.open_utf8(resource_file_path, 'w') as file:
                file.write(header)
                for item in items:
                    file.write(item)
                file.write(remainder)

            if namespace is None:
                self.nonnamespaced_resources_result.append(resource_name)
            else:
                self.namespaced_resources_result_map.setdefault(namespace, []).append(resource_name)

            self.total_files += 1


class DownloaderPayload:
    def __init__(self, namespace: Optional[str], resources: List[str]):
        self.namespace = namespace
        self.resources = resources


class DownloaderTasksQueue(Iterator[DownloaderPayload]):
    def __init__(self,
                 namespaces: List[Dict[str, str]],
                 namespaced_resources: List[Dict[str, str]],
                 nonnamespaced_resources: List[Dict[str, str]]
                 ):
        self.namespaces = namespaces
        self.namespaced_resources = namespaced_resources
        self.nonnamespaced_resources = nonnamespaced_resources
        self._tasks = self._unsafe_tasks()
        self._lock = threading.Lock()

    def __next__(self) -> DownloaderPayload:
        with self._lock:
            return next(self._tasks)

    def _unsafe_tasks(self) -> Iterator[DownloaderPayload]:
        yield DownloaderPayload(None, [r['name'] for r in self.nonnamespaced_resources])

        for namespace in self.namespaces:
            yield DownloaderPayload(namespace['name'], [r['name'] for r in self.namespaced_resources])


class DownloadException(Exception):
    def __init__(self, task: DownloaderPayload, reason: BaseException):
        self.task = task
        self.reason = reason


class ExportKubernetesDownloader:
    def __init__(self,
                 backup_directory: str,
                 control_plane: NodeGroup,
                 cluster: KubernetesCluster,
                 tasks_queue: Iterator[DownloaderPayload],
                 parser: ExportKubernetesParser,
                 ):
        self.backup_directory = backup_directory
        self.control_plane = control_plane
        self.connection_pool = cluster.create_connection_pool(control_plane.get_hosts())
        self.tasks_queue = tasks_queue
        self.parser = parser
        self.elapsed: float = 0

    def run(self) -> None:
        start = time.time()
        task: Optional[DownloaderPayload] = None
        try:
            while True:
                if self.parser.closed:
                    # No need to continue as the parser is already closed due to error.
                    break

                task = next(self.tasks_queue, None)
                if task is None:
                    break

                # Skip task with empty resource list
                if not task.resources:
                    continue

                random = uuid.uuid4().hex
                temp_local_filepath = os.path.join(self.backup_directory, random)
                self._download(task, temp_local_filepath)

                self.parser.schedule(ParserPayload("do", temp_local_filepath, task.namespace))
        except BaseException as e:
            self.parser.finish(graceful=False)
            if task is not None:
                raise DownloadException(task, e)
            else:
                raise
        else:
            self.parser.finish(graceful=True)
        finally:
            self.elapsed = time.time() - start
            self.connection_pool.close()

    def _download(self, task: DownloaderPayload, temp_local_filepath: str) -> None:
        namespace = task.namespace
        temp_remote_filepath = f"/tmp/{os.path.basename(temp_local_filepath)}"

        cmd = f'(set -o pipefail && sudo kubectl ' \
              f'{"" if namespace is None else ("-n " + namespace + " ")}' \
              f'get --ignore-not-found ' \
              f'{",".join(r for r in task.resources)} ' \
              f'-o yaml | gzip -c) > {temp_remote_filepath}'

        # Use own connection instance to run commands
        with RemoteExecutor(self.control_plane, self.connection_pool) as exe:
            group = exe.group
            group.run(cmd)
            group.get(temp_remote_filepath, temp_local_filepath)
            group.sudo(f'rm {temp_remote_filepath}')


def export_kubernetes(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)
    control_plane = cluster.nodes['control-plane'].get_any_member()
    backup_kubernetes = cluster.procedure_inventory.get('backup_plan', {}).get('kubernetes', {})
    logger = cluster.log

    logger.debug('Loading namespaces:')
    loaded_namespaces = _load_namespaces(logger, control_plane)
    proposed_namespaces = backup_kubernetes.get('namespaced_resources', {}).get('namespaces', 'all')
    namespaces = _filter_resources_by_proposed(logger, loaded_namespaces, proposed_namespaces, 'namespace')

    logger.debug('Loading namespaced resource types:')
    loaded_resources = _load_resources(logger, control_plane, True)
    proposed_resources = backup_kubernetes.get('namespaced_resources', {}).get('resources', [])
    namespaced_resources = _filter_resources_by_proposed(logger, loaded_resources, proposed_resources, 'resource')

    logger.debug('Loading non-namespaced resource types:')
    loaded_resources = _load_resources(logger, control_plane, False)
    proposed_resources = backup_kubernetes.get('nonnamespaced_resources', [])
    nonnamespaced_resources = _filter_resources_by_proposed(logger, loaded_resources, proposed_resources, 'resource')

    logger.debug('Loading resources:')
    start = time.time()

    # Processing of the particular resource includes
    # 1. downloading of the `kubectl` result (mostly IO)
    # 2. parsing and splitting it into files (can potentially consume CPU)
    control_planes = cluster.nodes['control-plane']
    downloaders_per_control_plane = 2

    parser = ExportKubernetesParser(logger, backup_directory, namespaced_resources, nonnamespaced_resources,
                                    control_planes.nodes_amount() * downloaders_per_control_plane)
    downloader_queue = DownloaderTasksQueue(namespaces, namespaced_resources, nonnamespaced_resources)
    downloaders = [
        ExportKubernetesDownloader(backup_directory, control_plane, cluster,
                                   downloader_queue, parser)
        for _ in range(downloaders_per_control_plane)
        for control_plane in control_planes.get_ordered_members_list()
    ]

    logger.debug(f'Using {len(downloaders)} workers to download resources.')

    with ThreadPoolExecutor(max_workers=len(downloaders) + 1) as tpe:
        downloaders_async = [tpe.submit(downloader.run) for downloader in downloaders]
        parser_async = tpe.submit(parser.run)

        def _graceful_shutdown_downloaders() -> Optional[BaseException]:
            # Although parser may exit successfully, not all resources might be processed due to errors in downloaders.
            # Choose any error in such case.
            exc: Optional[BaseException] = None
            for downloader_async in downloaders_async:
                try:
                    downloader_async.result()
                except BaseException as e:
                    logger.verbose(e)
                    if isinstance(e, DownloadException):
                        logger.error(f"Failed to download resources {','.join(e.task.resources)} for namespace {e.task.namespace}")
                        exc = e.reason
                    else:
                        exc = e

            return exc

        try:
            # Wait for successful parsing of resources or till exception.
            parser_async.result()
        except BaseException:
            # Wait for graceful exiting of downloaders after their currently running command is finished.
            # If few background tasks fail, the parser exception has priority, and the other is logged.
            _graceful_shutdown_downloaders()
            raise

        downloader_exception = _graceful_shutdown_downloaders()
        if downloader_exception is not None:
            raise downloader_exception

    downloaded_resources_descriptor = cluster.context['backup_descriptor']['kubernetes']['resources']
    if parser.namespaced_resources_result_map:
        downloaded_resources_descriptor['namespaced'] = parser.namespaced_resources_result_map

    if parser.nonnamespaced_resources_result:
        downloaded_resources_descriptor['nonnamespaced'] = parser.nonnamespaced_resources_result

    logger.verbose(f'Downloading elapsed: {max(downloader.elapsed for downloader in downloaders)}')
    logger.verbose(f'Parsing elapsed: {parser.elapsed}')
    logger.verbose(f'Total elapsed: {time.time() - start}')
    logger.verbose(f'Total files saved: {parser.total_files}')


def make_descriptor(cluster: KubernetesCluster) -> None:
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)

    cluster.context['backup_descriptor']['kubernetes']['thirdparties'] = cluster.inventory['services']['thirdparties']
    cluster.context['backup_descriptor']['meta']['time']['finished'] = datetime.datetime.now()

    with utils.open_external(os.path.join(backup_directory, 'descriptor.yaml'), 'w') as output:
        output.write(yaml.dump(cluster.context['backup_descriptor']))


def pack_data(cluster: KubernetesCluster) -> None:
    cluster_name = cluster.inventory['cluster_name']
    backup_directory = prepare_backup_tmpdir(cluster.log, cluster.context)

    backup_filename = 'backup-%s-%s.tar.gz' % (cluster_name, utils.get_current_timestamp_formatted())

    target = utils.get_external_resource_path(cluster.procedure_inventory.get('backup_location', backup_filename))
    if os.path.isdir(target):
        target = os.path.join(target, backup_filename)

    cluster.log.debug('Packing all data...')
    pack_to_tgz(target, backup_directory)

    cluster.log.verbose('Cleaning up...')
    shutil.rmtree(backup_directory, ignore_errors=True)


def pack_to_tgz(target_archive: str, source_dir: str) -> None:
    with tarfile.open(target_archive, "w:gz") as tar_handle:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                pathname = os.path.join(root, file)
                tar_handle.add(pathname, pathname.replace(source_dir, ''))
        tar_handle.close()


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


def create_context(cli_arguments: List[str] = None) -> dict:
    cli_help = '''
    Script for making backup of Kubernetes resources and nodes contents.

    How to use:

    '''

    parser = flow.new_procedure_parser(cli_help, tasks=tasks, optional_config=True)

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

    return context


def main(cli_arguments: List[str] = None) -> None:
    context = create_context(cli_arguments)
    flow.ActionsFlow([BackupAction()]).run_flow(context)


if __name__ == '__main__':
    main()
