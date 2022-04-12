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

    buf = io.StringIO()
    ruamel_yaml.dump(final_inventory, buf)
    cluster_orig = buf.getvalue()
    dump_file(cluster, cluster_orig, "cluster.yaml")

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

    if cluster.context.get("dump_filename_prefix"):
        filename = f"{cluster.context['dump_filename_prefix']}_{filename}"

    if not cluster.context['execution_arguments'].get('disable_dump', True):
        with open(get_resource_absolute_path(cluster.context['execution_arguments']['dump_location'] + '/' + filename),
                  'w') as file:
            file.write(data)


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
        self.dir_path = "/etc/kubemarine/kube_tasks/"
        self.dir_name = ''
        self.dir_location = ''
        self.cluster.log.debug("New storage created")

    @classmethod
    def get_instance(cls, cluster):
        if not cls.__instance:
            cls.__instance = ClusterStorage(cluster)
        return cls.__instance

    def _make_dir(self, cluster):
        """
        This method creates a directory in which logs about operations on the cluster will be stored.
        """
        readable_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        initial_procedure = cluster.context["initial_procedure"]
        self.dir_name = readable_timestamp + "_" + initial_procedure + "/"
        self.dir_location = self.dir_path + self.dir_name
        cluster.nodes['master'].run(f"sudo mkdir -p {self.dir_location} ; sudo rm {self.dir_path + 'latest_dump'} ;"
                                     f" sudo ln -s {self.dir_location} {self.dir_path + 'latest_dump'}")

    def rotation_file(self, cluster):
        """
        This method packs files with logs and maintains a structured storage of logs on the cluster.
        """

        for node in self.cluster.nodes['master'].get_ordered_members_list(provide_node_configs=True):
            group = cluster.make_group([node['connect_to']])
            command_count = f'ls {self.dir_path} -l |  egrep "^d|tar.gz" | wc -l'
            count = int(group.sudo(command_count).get_simple_out())
            command = f'ls {self.dir_path} | grep -v latest_dump'
            sum_file = group.sudo(command).get_simple_out()
            files = sum_file.split()
            files.sort(reverse=True)
            files_unsort = sum_file.split()
            not_pack_file = cluster.defaults['procedure_history']['not_archive_threshold']
            delete_old = cluster.defaults['procedure_history']['delete_threshold']
            if count > not_pack_file:
                for i in range(not_pack_file, delete_old):
                    if 'tar.gz' not in files[i] and i < count:
                        group.sudo(f'tar -czvf {self.dir_path + files[i] + ".tar.gz"} {self.dir_path + files[i]}')
                        group.sudo(f'rm -r {self.dir_path + files[i]}')
                    break
            if count > delete_old:
                for i in range(len(files_unsort)):
                    diff = count - delete_old
                    if i < diff:
                        cluster.log.verbose('Deleting backup file from nodes...')
                        group.sudo(f'rm -r {self.dir_path + files_unsort[i]}')

    def comprese_and_upload_archive(self, cluster):
        """
        This method compose dump files and sends the collected files to the nodes.
        """
        if self.cluster.context["initial_procedure"] == 'paas':
            self.cluster.log.verbose(self.cluster.context["initial_procedure"] + ' procedure')
        elif self.cluster.context["initial_procedure"] == 'iaas':
            self.cluster.log.verbose(self.cluster.context["initial_procedure"] + ' procedure')
        else:
            if self.cluster.context["initial_procedure"] != None:
                self._make_dir(cluster)
                dump_dir = self.cluster.context['execution_arguments']['dump_location']
                files_dump = {
                      'procedure_parameters':'procedure_parameters',
                      'version':'version',
                      'cluster_precompiled.yaml':'cluster_precompiled.yaml',
                      'cluster.yaml':'cluster.yaml',
                      'cluster_default.yaml':'cluster_default.yaml',
                      'cluster_finalized.yaml':'cluster_finalized.yaml',
                      'procedure.yaml': 'procedure.yaml'
                      }
                onlyfiles = [f for f in listdir(dump_dir) if isfile(join(dump_dir, f))]
                archive = dump_dir + "local.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    for name, path in files_dump.items():
                        if name in onlyfiles:
                            output = dump_dir + path
                            tar.add(output)
        self.cluster.nodes['master'].put(archive, self.dir_location + 'local.tar.gz', sudo=True, binary=False)
        self.cluster.log.debug('File download local.tar.gz')
        self.cluster.nodes['master'].sudo(f'tar -C {self.dir_location} -xzvf {self.dir_location + "local.tar.gz"} --strip-components=2 ')
        self.cluster.nodes['master'].sudo(f'rm -f {self.dir_location + "local.tar.gz"} ')

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
            output = yaml.safe_load(stream)
            output = yaml.dump(output)
            dump_file(cluster, output, "version")


    def collect_info_all_master(self):
        """
        This method is used to transfer backup logs from the main master to the new master.
        """
        for node in self.cluster.nodes['master'].get_ordered_members_list(provide_node_configs=True):
            ip = node['address']
            if self.cluster.context['nodes'][ip]['online']:
                data_copy_res = self.cluster.nodes['master'].get_first_member().sudo(
                    f'tar -czvf /tmp/kubemarine-backup.tar.gz {self.dir_path}')
                self.cluster.log.debug('Backup created:\n%s' % data_copy_res)
                node['connection'].get('/tmp/kubemarine-backup.tar.gz',
                                       os.path.join(self.cluster.context['execution_arguments']['dump_location'],
                                                    'dump_log_cluster.tar.gz'))
                self.cluster.log.debug('Backup downloaded')
                return
            else:
                self.cluster.log.debug('Masters offline %s' % node['name'])
