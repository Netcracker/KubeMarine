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
import hashlib
import io
import json
import os
import shutil
import sys
import time
import tarfile

from typing import Tuple

import yaml
import ruamel.yaml
from copy import deepcopy
from datetime import datetime
from collections import OrderedDict

from ruamel.yaml import CommentedMap

from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.errors import pretty_print_error


def do_fail(message='', reason: Exception = None, hint='', log=None):

    if log:
        log.critical('FAILURE!')
        if message != "":
            log.critical(message)
    else:
        sys.stderr.write("\033[91mFAILURE!")
        if message != "":
            sys.stderr.write(" - " + message + "\n")

    pretty_print_error(reason, log)

    sys.stderr.write("\n")

    # Please do not rewrite this to logging approach:
    # hint should be visible only in stdout and without special formatting
    if hint != "":
        sys.stderr.write(hint)

    if not log:
        sys.stderr.write("\033[0m\n")

    sys.exit(1)


def get_elapsed_string(start, end):
    elapsed = end - start
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    return '{:02}h {:02}m {:02}s'.format(int(hours), int(minutes), int(seconds))


def prepare_dump_directory(location, reset_directory=True):
    dumpdir = os.path.join(location, 'dump')
    if reset_directory and os.path.exists(dumpdir) and os.path.isdir(dumpdir):
        shutil.rmtree(dumpdir)
    os.makedirs(dumpdir, exist_ok=True)


def make_ansible_inventory(location, cluster):

    inventory = get_final_inventory(cluster)
    roles = []
    for node in inventory['nodes']:
        for role in node['roles']:
            if role not in roles:
                roles.append(role)

    config = {
        'all': [
            'localhost ansible_connection=local'
        ],
        'cluster:children': []
    }

    already_global_defined = []

    for role in roles:
        config[role] = []
        config['cluster:children'].append(role)
        for node in cluster.nodes[role].get_final_nodes().get_ordered_members_list(provide_node_configs=True):
            record = "%s ansible_host=%s ansible_ssh_user=%s ansible_ssh_private_key_file=%s ip=%s" % \
                     (node['name'],
                      node['connect_to'],
                      node.get('username', cluster.globals['connection']['defaults']['username']),
                      node['keyfile'],
                      node['internal_address'])
            if node.get('address') is not None:
                record += ' external_ip=%s' % node['address']

            if node['name'] not in already_global_defined:
                config['all'].append(record)
                # to avoid duplicate definition in global section we have to check is that was already defined?
                already_global_defined.append(node['name'])

            config[role].append(node['name'])

    config['cluster:vars'] = [
        'ansible_become=True'
    ]

    for group in ['services', 'plugins']:
        if inventory.get(group) is not None:
            for service_name, service_configs in inventory[group].items():
                # write to inventory only plugins, which will be installed
                if group != 'plugins' or service_configs.get('install', False):

                    config['cluster:vars'].append('\n# %s.%s' % (group, service_name))

                    if isinstance(service_configs, dict):

                        if service_configs.get('installation') is not None:
                            del service_configs['installation']
                        if service_configs.get('install') is not None:
                            del service_configs['install']

                        for config_name, config_value in service_configs.items():
                            if isinstance(config_value, dict) or isinstance(config_value, list):
                                config_value = json.dumps(config_value)
                            config['cluster:vars'].append('%s_%s=%s' % (
                                # TODO: Rewrite replace using regex
                                service_name.replace('-', '_').replace('.', '_').replace('/', '_'),
                                config_name.replace('-', '_').replace('.', '_').replace('/', '_'),
                                config_value))
                    else:
                        config_value = json.dumps(service_configs)
                        config['cluster:vars'].append('%s=%s' % (
                            service_name.replace('-', '_').replace('.', '_'),
                            config_value))

    config_compiled = ''
    for section_name, strings in config.items():
        config_compiled += '[%s]' % section_name
        for string in strings:
            config_compiled += '\n' + string
        config_compiled += '\n\n'

    dump_file({}, config_compiled, location, dump_location=False)


def get_current_timestamp_formatted():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def get_final_inventory(cluster, initial_inventory=None):
    if initial_inventory is None:
        inventory = deepcopy(cluster.inventory)
    else:
        inventory = deepcopy(initial_inventory)

    from kubemarine import admission, kubernetes, packages, plugins, thirdparties
    from kubemarine.plugins import nginx_ingress
    from kubemarine.procedures import add_node, remove_node, migrate_cri

    inventory_finalize_functions = {
        add_node.add_node_finalize_inventory,
        remove_node.remove_node_finalize_inventory,
        kubernetes.upgrade_finalize_inventory,
        thirdparties.upgrade_finalize_inventory,
        plugins.upgrade_finalize_inventory,
        packages.upgrade_finalize_inventory,
        admission.finalize_inventory,
        nginx_ingress.finalize_inventory,
        migrate_cri.migrate_cri_finalize_inventory
    }

    for finalize_fn in inventory_finalize_functions:
        inventory = finalize_fn(cluster, inventory)

    return inventory


def merge_vrrp_ips(procedure_inventory, inventory):
    if "vrrp_ips" in inventory and len(inventory["vrrp_ips"]) > 0:
        raise Exception("vrrp_ips section already defined, merging not supported yet")
    else:
        inventory["vrrp_ips"] = procedure_inventory["vrrp_ips"]

    if isinstance(inventory, OrderedDict):
        inventory.move_to_end("vrrp_ips", last=False)


def dump_file(context, data: object, filename: str,
              *, dump_location=True):
    if dump_location:
        if not isinstance(context, dict):
            # cluster is passed instead of the context directly
            cluster = context
            context = cluster.context

        args = context['execution_arguments']
        if args.get('disable_dump', True) \
                and not (filename in ClusterStorage.PRESERVED_DUMP_FILES and context['preserve_inventory']):
            return

        prepare_dump_directory(args.get('dump_location'), reset_directory=False)
        target_path = get_dump_filepath(context, filename)
    else:
        target_path = get_external_resource_path(filename)

    if isinstance(data, io.StringIO):
        data = data.getvalue()
    if isinstance(data, io.TextIOWrapper):
        data = data.read()

    with open_utf8(target_path, 'w') as file:
        file.write(data)


def get_dump_filepath(context, filename):
    if context.get("dump_filename_prefix"):
        filename = f"{context['dump_filename_prefix']}_{filename}"

    return get_external_resource_path(os.path.join(context['execution_arguments']['dump_location'], 'dump', filename))


def wait_command_successful(group, command, retries=15, timeout=5, warn=True, hide=False, is_async=True):
    log = group.cluster.log

    while retries > 0:
        log.debug("Waiting for command to succeed, %s retries left" % retries)
        result = group.sudo(command, warn=warn, hide=hide, is_async=is_async)
        exit_code = list(result.values())[0].exited
        if exit_code == 0:
            log.debug("Command succeeded")
            return
        retries = retries - 1
        time.sleep(timeout)
    raise Exception("Command failed")


def open_utf8(path: str, mode='r'):
    return open(path, mode + 't', encoding='utf-8')


def open_internal(path: str, mode='r'):
    return open_utf8(get_internal_resource_path(path), mode)


def open_external(path: str, mode='r'):
    return open_utf8(get_external_resource_path(path), mode)


def read_internal(path: str) -> str:
    with open_internal(path) as f:
        return f.read()


def read_external(path: str) -> str:
    with open_external(path) as f:
        return f.read()


def get_external_resource_path(path):
    return os.path.abspath(path)


def get_internal_resource_path(path: str) -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', path)
    )


def determine_resource_absolute_file(path: str) -> Tuple[str, bool]:
    """
    Get and verify absolute path to resource file
    :param path: Relative path to resource
    :return: Tuple of absolute path to resource file and flag defining if is an external resource
    """
    # is resource exists as it is defined?
    initial_definition = get_external_resource_path(path)
    if os.path.isfile(initial_definition):
        return initial_definition, True

    # is resource exists as internal resource?
    patched_definition = get_internal_resource_path(path)
    if os.path.isfile(patched_definition):
        return patched_definition, False

    raise Exception('Requested resource %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


def determine_resource_absolute_dir(path: str) -> Tuple[str, bool]:
    """
    Get and verify absolute path to resource directory
    :param path: Relative path to resource
    :return: Tuple of absolute path to resource directory and flag defining if is an external resource
    """
    dirname = os.path.dirname(path)
    # is resource dir exists as it is defined?
    initial_definition = get_external_resource_path(dirname)
    if os.path.isdir(initial_definition):
        return initial_definition, True

    # is resource dir exists as internal resource?
    patched_definition = get_internal_resource_path(dirname)
    if os.path.isdir(patched_definition):
        return patched_definition, False

    raise Exception(
        'Requested resource directory %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


def get_local_file_sha1(filename: str) -> str:
    sha1 = hashlib.sha1()

    # Read local file by chunks of 2^16 bytes (65536) and calculate aggregated SHA1
    with open(filename, 'rb') as f:
        while True:
            data = f.read(2 ** 16)
            if not data:
                break
            sha1.update(data)

    return sha1.hexdigest()


def yaml_structure_preserver() -> ruamel.yaml.YAML:
    """YAML loader and dumper which saves original structure"""
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.preserve_quotes = True
    return ruamel_yaml


def is_sorted(l: list, key: callable = None) -> bool:
    """
    Check that the specified list is sorted.

    :param l: list to check
    :param key: custom key function to customize the sort order
    :return: boolean flag if the list is sorted
    """
    if key is None:
        key = lambda x: x
    return all(key(l[i]) <= key(l[i + 1]) for i in range(len(l) - 1))


def map_sorted(map_: CommentedMap, key: callable = None) -> CommentedMap:
    """
    Check that the specified CommentedMap is sorted, or create new sorted map from it otherwise.

    :param map_: CommentedMap instance to check
    :param key: custom key function to customize the sort order of the map keys
    :return: the same or new sorted instance of the map
    """
    if key is None:
        key = lambda x: x
    map_keys = list(map_)
    if not is_sorted(map_keys, key=key):
        map_ = CommentedMap(sorted(map_.items(), key=lambda item: key(item[0])))

    return map_

def insert_map_sorted(map_: CommentedMap, k, v, key: callable = None) -> None:
    """
    Insert new item to the CommentedMap or update the value for the existing key.
    The map should be already sorted.

    :param map_: sorted CommentedMap instance
    :param k: new key
    :param v: new value
    :param key: custom key function to customize the sort order of the map keys
    """
    if k in map_:
        map_[k] = v
        return

    if key is None:
        key = lambda x: x
    # Find position to insert new item maintaining the order
    pos = max((mi + 1 for mi, mv in enumerate(map_)
               if key(mv) < key(k)),
              default=0)

    map_.insert(pos, k, v)


def load_yaml(filepath) -> dict:
    try:
        with open_utf8(filepath, 'r') as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        do_fail(f"Failed to load {filepath}", exc)


def true_or_false(value):
    """
    The method check string and boolean value
    :param value: Value that should be checked
    """
    input_string = str(value)
    if input_string in ['true', 'True', 'TRUE']:
        result = "true"
    elif input_string in ['false', 'False', 'FALSE']:
        result = "false"
    else:
        result = "undefined"
    return result


def get_version_filepath():
    return get_internal_resource_path("version")


def get_version():
    return read_internal(get_version_filepath()).strip()


def minor_version(version: str) -> str:
    """
    Converts vN.N.N to vN.N
    """
    return 'v' + '.'.join(map(str, _test_version(version, 3)[0:2]))


def version_key(version: str) -> Tuple[int, int, int]:
    """
    Converts vN.N.N to (N, N, N) that can be used in comparisons.
    """
    return tuple(_test_version(version, 3))


def minor_version_key(version: str) -> Tuple[int, int]:
    """
    Converts vN.N to (N, N) that can be used in comparisons.
    """
    return tuple(_test_version(version, 2))


def _test_version(version: str, numbers_amount: int) -> list:
    # catch version without "v" at the first symbol
    if version.startswith('v'):
        version_list: list = version[1:].split('.')
        # catch invalid version 'v1.16'
        if len(version_list) == numbers_amount:
            # parse str to int and catch invalid symbols in version number
            try:
                for i, value in enumerate(version_list):
                    # whitespace required because python's int() ignores them
                    version_list[i] = int(value.replace(' ', '.'))
            except ValueError:
                pass
            else:
                return version_list

    expected_pattern = 'v' + '.'.join('N+' for _ in range(numbers_amount))
    raise ValueError(f'Incorrect version \"{version}\" format, expected version pattern is \"{expected_pattern}\"')


class ClusterStorage:
    """
    File preservation:
    1- Create folder where dumps are stored
    2- Rotating dumps in the storage folder
    3- Uploading dumps to nodes
    4- Copying dumps to new nodes
    """

    PRESERVED_DUMP_FILES = ['procedure.yaml', 'procedure_parameters', 'cluster_precompiled.yaml',
                            'cluster.yaml','cluster_initial.yaml', 'cluster_finalized.yaml']

    def __init__(self, cluster):
        from kubemarine.core.cluster import KubernetesCluster
        self.cluster: KubernetesCluster = cluster
        self.dir_path = "/etc/kubemarine/procedures/"
        self.dir_name = ''
        self.dir_location = ''

    def make_dir(self):
        """
        This method creates a directory in which logs about operations on the cluster will be stored.
        """
        readable_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        initial_procedure = self.cluster.context["initial_procedure"]
        self.dir_name = readable_timestamp + "_" + initial_procedure + "/"
        self.dir_location = self.dir_path + self.dir_name
        self.cluster.nodes['control-plane'].get_final_nodes().sudo(f"mkdir -p {self.dir_location} ; sudo rm {self.dir_path + 'latest_dump'} ;"
                                                 f" sudo ln -s {self.dir_location} {self.dir_path + 'latest_dump'}")

    def rotation_file(self):
        """
        This method packs files with logs and maintains a structured storage of logs on the cluster.
        """
        not_pack_file = self.cluster.inventory['procedure_history']['archive_threshold']
        delete_old = self.cluster.inventory['procedure_history']['delete_threshold']

        command = f'ls {self.dir_path} | grep -v latest_dump'
        node_group_results = self.cluster.nodes["control-plane"].get_final_nodes().sudo(command)
        with RemoteExecutor(self.cluster):
            for cxn, result in node_group_results.items():
                control_plane = self.cluster.make_group([cxn.host])
                files = result.stdout.split()
                files.sort(reverse=True)
                for i, file in enumerate(files):
                    if i >= not_pack_file and i < delete_old:
                        if 'tar.gz' not in file:
                            control_plane.sudo(f'tar -czvf {self.dir_path + file + ".tar.gz"} {self.dir_path + file} &&'
                                       f'sudo rm -r {self.dir_path + file}')
                    elif i >= delete_old:
                        control_plane.sudo(f'rm -rf {self.dir_path + file}')

    def compress_and_upload_archive(self):
        """
        This method compose dump files and sends the collected files to the nodes.
        """
        context = self.cluster.context
        archive = get_dump_filepath(context, "local.tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            for name in ClusterStorage.PRESERVED_DUMP_FILES:
                source = get_dump_filepath(context, name)
                if os.path.exists(source):
                    tar.add(source, 'dump/' + name)
            tar.add(context['execution_arguments']['config'], 'cluster.yaml')
            tar.add(get_version_filepath(), 'version')

        self.cluster.log.debug('Uploading archive with preserved information about the procedure.')
        self.cluster.nodes['control-plane'].get_final_nodes().put(archive, self.dir_location + 'local.tar.gz', sudo=True)
        self.cluster.nodes['control-plane'].get_final_nodes().sudo(f'tar -C {self.dir_location} -xzv --no-same-owner -f {self.dir_location + "local.tar.gz"}  && '
                                                 f'sudo rm -f {self.dir_location + "local.tar.gz"} ')

    def collect_procedure_info(self):
        """
        This method collects information about the type of procedure and the version of the tool we are working with.
        """
        context = self.cluster.context
        out = dict()
        out['arguments'] = context['initial_cli_arguments']
        if 'proceeded_tasks' in context:
            out['finished_tasks'] = context['proceeded_tasks']
        out["initial_procedure"] = context["initial_procedure"]
        out["successfully_performed"] = context["successfully_performed"]
        out['status'] = context['status']
        output = yaml.dump(out)
        dump_file(context, output, "procedure_parameters")

    def upload_info_new_control_planes(self):
        """
        This method is used to transfer backup logs from the initial control-plane to the new control-planes.
        """
        new_control_planes = self.cluster.nodes['control-plane'].get_new_nodes()
        if new_control_planes.is_empty():
            return

        archive_name = 'dump_log_cluster.tar.gz'
        archive_dump_path = get_dump_filepath(self.cluster.context, archive_name)
        archive_remote_path = f"/tmp/{archive_name}"
        log = self.cluster.log

        node = self.cluster.nodes['control-plane'].get_initial_nodes().get_first_member(provide_node_configs=True)
        control_plane = self.cluster.make_group([node['connect_to']])
        data_copy_res = control_plane.sudo(f'tar -czvf {archive_remote_path} {self.dir_path}')
        log.verbose("Archive with procedures history is created:\n%s" % data_copy_res)
        control_plane.get(archive_remote_path, archive_dump_path)

        log.debug("Archive with procedures history is downloaded")

        for new_node in new_control_planes.get_ordered_members_list(provide_node_configs=True):
            group = self.cluster.make_group([new_node['connect_to']])
            group.put(archive_dump_path, archive_remote_path, sudo=True)
            group.sudo(f'tar -C / -xzvf {archive_remote_path}')
            log.debug(f"Archive with procedures history is uploaded to {new_node['name']!r}")
