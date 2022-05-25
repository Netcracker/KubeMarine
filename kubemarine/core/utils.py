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

from os import listdir
from os.path import isfile, join
from typing import Union

import yaml
import ruamel.yaml
from copy import deepcopy
from datetime import datetime
from collections import OrderedDict

from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.errors import pretty_print_error
from kubemarine.plugins import nginx_ingress


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
                if group != 'plugins' or service_configs.get('install', False) is True:

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

    with open(location, 'w') as configfile:
        configfile.write(config_compiled)


def get_current_timestamp_formatted():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def recreate_final_inventory_file(cluster):
    # load inventory as ruamel.yaml to save original structure
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.preserve_quotes = True
    with open(get_resource_absolute_path(cluster.context['execution_arguments']['config']), "r") as stream:
        initial_inventory = ruamel_yaml.load(stream)

        # write original file data to backup file with timestamp
        timestamp = get_current_timestamp_formatted()
        inventory_file_basename = os.path.basename(cluster.context['execution_arguments']['config'])
        dump_file(cluster, stream, "%s_%s" % (inventory_file_basename, str(timestamp)))

    # convert initial inventory to final
    final_inventory = get_final_inventory(cluster, initial_inventory=initial_inventory)

    # replace intial inventory with final one
    with open(get_resource_absolute_path(cluster.context['execution_arguments']['config']), "w+") as stream:
        ruamel_yaml.dump(final_inventory, stream)


def get_final_inventory(cluster, initial_inventory=None):
    if initial_inventory is None:
        inventory = deepcopy(cluster.inventory)
    else:
        inventory = deepcopy(initial_inventory)

    from kubemarine import admission
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


def dump_file(cluster, data, filename):
    if isinstance(data, io.StringIO):
        data = data.getvalue()
    if isinstance(data, io.TextIOWrapper):
        data = data.read()

    if cluster.context["initial_procedure"] != None:
        file_path = get_dump_filepath(cluster, filename)
        if not cluster.context['execution_arguments'].get('disable_dump', True):
            with open(get_resource_absolute_path(file_path),
                      'w') as file:
                file.write(data)
        else:
            files_obligatory = ['procedure.yaml', 'procedure_parameters','cluster_precompiled.yaml',
                              'cluster.yaml','cluster_initial.yaml', 'cluster_finalized.yaml','version']
            prepare_dump_directory(get_resource_absolute_path(cluster.context['execution_arguments'].get('dump_location')))
            if filename in files_obligatory:
                with open(get_resource_absolute_path(file_path),
                          'w') as file:
                    file.write(data)

def get_dump_filepath(cluster, filename):
    if cluster.context.get("dump_filename_prefix"):
        filename = f"{cluster.context['dump_filename_prefix']}_{filename}"

    return get_resource_absolute_path(cluster.context['execution_arguments']['dump_location']+'/'+filename)



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


def get_resource_absolute_path(path, script_relative=False):
    initial_relative = ''
    if script_relative:
        initial_relative = os.path.dirname(__file__) + '/../'
    return os.path.abspath(initial_relative + path)


def determine_resource_absolute_path(path):
    # is resource exists as it is defined?
    initial_definition = get_resource_absolute_path(path, script_relative=False)
    if os.path.isfile(initial_definition):
        return initial_definition

    # is resource exists as internal resource?
    patched_definition = get_resource_absolute_path(path, script_relative=True)
    if os.path.isfile(patched_definition):
        return patched_definition

    raise Exception('Requested resource %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


def get_resource_absolute_dir(path: str, script_relative=False) -> str:
    """
    Get absolute path to resource directory
    :param path: Relative path to resource
    :param script_relative: True, if resource is internal
    :return: Absolute path to resource directory
    """
    initial_relative = ''
    if script_relative:
        initial_relative = os.path.dirname(__file__) + '/../'
    return os.path.abspath(os.path.dirname(initial_relative + path))


def determine_resource_absolute_dir(path: str) -> str:
    """
    Get and verify absolute path to resource directory
    :param path: Relative path to resource
    :return: Absolute path to resource directory
    """
    # is resource dir exists as it is defined?
    initial_definition = get_resource_absolute_dir(path, script_relative=False)
    if os.path.isdir(initial_definition):
        return initial_definition

    # is resource dir exists as internal resource?
    patched_definition = get_resource_absolute_dir(path, script_relative=True)
    if os.path.isdir(patched_definition):
        return patched_definition

    raise Exception(
        'Requested resource directory %s is not exists at %s or %s' % (path, initial_definition, patched_definition))


class ClusterStorage:
    """
    File preservation:
    1- Create folder where dumps are stored
    2- Rotating dumps in the storage folder
    3- Uploading dumps to nodes
    4- Copying dumps to new nodes
    """
    __instance = None

    def __init__(self, cluster):
        self.cluster = cluster
        self.dir_path = "/etc/kubemarine/procedures/"
        self.dir_name = ''
        self.dir_location = ''
        self.cluster.log.debug("New storage created")

    @classmethod
    def get_instance(cls, cluster):
        if not cls.__instance:
            cls.__instance = ClusterStorage(cluster)
        return cls.__instance

    def make_dir(self, cluster):
        """
        This method creates a directory in which logs about operations on the cluster will be stored.
        """
        readable_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        initial_procedure = cluster.context["initial_procedure"]
        self.dir_name = readable_timestamp + "_" + initial_procedure + "/"
        self.dir_location = self.dir_path + self.dir_name
        cluster.nodes['control-plane'].sudo(f"mkdir -p {self.dir_location} ; sudo rm {self.dir_path + 'latest_dump'} ;"
                                     f" sudo ln -s {self.dir_location} {self.dir_path + 'latest_dump'}")

    def rotation_file(self, cluster):
        """
        This method packs files with logs and maintains a structured storage of logs on the cluster.
        """
        not_pack_file = cluster.inventory['procedure_history']['archive_threshold']
        delete_old = cluster.inventory['procedure_history']['delete_threshold']


        command = f'ls {self.dir_path} | grep -v latest_dump'
        node_group_results = self.cluster.nodes["control-plane"].sudo(command)
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


    def compress_and_upload_archive(self, cluster):
        """
        This method compose dump files and sends the collected files to the nodes.
        """
        if self.cluster.context["initial_procedure"] != None:
            files_dump = ['procedure.yaml', 'procedure_parameters','cluster_precompiled.yaml',
                          'cluster.yaml','cluster_initial.yaml', 'cluster_finalized.yaml']
            archive = get_dump_filepath(cluster,"local.tar.gz")
            with tarfile.open(archive, "w:gz") as tar:
                for name in files_dump:
                    source = get_dump_filepath(cluster, name)
                    if os.path.exists(source):
                        tar.add(source, 'dump/' + name)
                tar.add(cluster.context['execution_arguments']['config'], 'cluster.yaml')
                tar.add(get_dump_filepath(cluster,"version"), 'version')
            self.cluster.nodes['control-plane'].put(archive, self.dir_location + 'local.tar.gz', sudo=True)
            self.cluster.log.debug('File upload local.tar.gz')
            self.cluster.nodes['control-plane'].sudo(f'tar -C {self.dir_location} -xzv --no-same-owner -f {self.dir_location + "local.tar.gz"}  && '
                                              f'sudo rm -f {self.dir_location + "local.tar.gz"} ')

    def collect_procedure_info(self, cluster):
        """
        This method collects information about the type of procedure and the version of the tool we are working with.
        """
        out = dict()
        execution_arguments = cluster.context.get('execution_arguments', {})
        out["tasks"] = execution_arguments["tasks"]
        out["exclude"] = execution_arguments["exclude"]
        out["initial_procedure"] = cluster.context["initial_procedure"]
        output = yaml.dump(out)
        dump_file(cluster, output, "procedure_parameters")


        with open(get_resource_absolute_path("version", script_relative=True), 'r') as stream:
            dump_file(cluster, stream, "version")


    def collect_info_all_control_plane(self, cluster):
        """
        This method is used to transfer backup logs from the main control-plane to the new control-plane.
        """

        node = self.cluster.nodes['control-plane'].get_initial_nodes().get_first_member(provide_node_configs=True)
        control_plane = cluster.make_group([node['connect_to']])
        data_copy_res = control_plane.sudo(f'tar -czvf /tmp/kubemarine-backup.tar.gz {self.dir_path}')
        self.cluster.log.debug('Backup created:\n%s' % data_copy_res)
        control_plane.get('/tmp/kubemarine-backup.tar.gz',
                                   get_dump_filepath(cluster, "dump_log_cluster.tar.gz"), 'dump_log_cluster.tar.gz')

        self.cluster.log.debug('Backup downloaded')


    def upload_info_new_node(self,cluster):

        new_nodes = cluster.nodes['all'].get_new_nodes()

        for new_node in new_nodes.get_ordered_members_list(provide_node_configs=True):
            group = cluster.make_group([new_node['connect_to']])
            if 'control-plane' in new_node['roles'] or 'control-plane' in new_node['roles']:
                group.put(get_dump_filepath(cluster, "dump_log_cluster.tar.gz"),
                    "/tmp/dump_log_cluster.tar.gz", sudo=True)
                group.sudo(f'tar -C / -xzvf /tmp/dump_log_cluster.tar.gz')
            else:
                cluster.log.debug('Control-plane not found')

