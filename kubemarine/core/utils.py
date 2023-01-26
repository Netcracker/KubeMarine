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
import os
import shutil
import sys
import time
import tarfile

from typing import Union, Tuple

import yaml
from copy import deepcopy
from datetime import datetime
from collections import OrderedDict

from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.errors import pretty_print_error


def do_fail(message='', reason: Union[str, Exception] = '', hint='', log=None):

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
    if reset_directory and os.path.exists(location) and os.path.isdir(location):
        shutil.rmtree(location)
    os.makedirs(location, exist_ok=True)


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

    with open_external(location, 'w') as configfile:
        configfile.write(config_compiled)


def get_current_timestamp_formatted():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def get_final_inventory(cluster, initial_inventory=None):
    if initial_inventory is None:
        inventory = deepcopy(cluster.inventory)
    else:
        inventory = deepcopy(initial_inventory)

    from kubemarine import admission
    from kubemarine.plugins import nginx_ingress
    from kubemarine.procedures import add_node, remove_node, upgrade, migrate_cri

    inventory_finalize_functions = {
        add_node.add_node_finalize_inventory,
        remove_node.remove_node_finalize_inventory,
        upgrade.upgrade_finalize_inventory,
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


def dump_file(context, data, filename):
    if not isinstance(context, dict):
        # cluster is passed instead of the context directly
        cluster = context
        context = cluster.context

    if isinstance(data, io.StringIO):
        data = data.getvalue()
    if isinstance(data, io.TextIOWrapper):
        data = data.read()

    args = context['execution_arguments']
    if not args.get('disable_dump', True) \
            or (filename in ClusterStorage.PRESERVED_DUMP_FILES and context['preserve_inventory']):

        prepare_dump_directory(args.get('dump_location'), reset_directory=False)
        with open_utf8(get_dump_filepath(context, filename), 'w') as file:
            file.write(data)


def get_dump_filepath(context, filename):
    if context.get("dump_filename_prefix"):
        filename = f"{context['dump_filename_prefix']}_{filename}"

    return get_external_resource_path(os.path.join(context['execution_arguments']['dump_location'], filename))


def wait_command_successful(group, command, retries=15, timeout=5, warn=True, hide=False):
    log = group.cluster.log

    while retries > 0:
        log.debug("Waiting for command to succeed, %s retries left" % retries)
        result = group.sudo(command, warn=warn, hide=hide)
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

        node = self.cluster.nodes['control-plane'].get_initial_nodes().get_first_member(provide_node_configs=True)
        control_plane = self.cluster.make_group([node['connect_to']])
        data_copy_res = control_plane.sudo(f'tar -czvf /tmp/kubemarine-backup.tar.gz {self.dir_path}')
        self.cluster.log.verbose('Backup created:\n%s' % data_copy_res)
        control_plane.get('/tmp/kubemarine-backup.tar.gz',
                          get_dump_filepath(self.cluster.context, "dump_log_cluster.tar.gz"), 'dump_log_cluster.tar.gz')

        self.cluster.log.debug('Backup downloaded')

        for new_node in new_control_planes.get_ordered_members_list(provide_node_configs=True):
            group = self.cluster.make_group([new_node['connect_to']])
            group.put(get_dump_filepath(self.cluster.context, "dump_log_cluster.tar.gz"),
                      "/tmp/dump_log_cluster.tar.gz", sudo=True)
            group.sudo(f'tar -C / -xzvf /tmp/dump_log_cluster.tar.gz')
