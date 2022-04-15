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

from copy import deepcopy

from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster


def enrich_inventory_apply_upgrade_defaults(inventory, cluster):
    if cluster.context.get('initial_procedure') == 'upgrade':
        upgrade_version = cluster.context["upgrade_version"]
        upgrade_thirdparties = cluster.procedure_inventory.get(upgrade_version, {}).get('thirdparties')
        if upgrade_thirdparties:
            upgrade_thirdparties = deepcopy(upgrade_thirdparties)
            default_thirdparties = cluster.defaults['services']['thirdparties']

            # keep some configurations (unpack) from default thirdparties, if they are not re-defined
            for destination, config in upgrade_thirdparties.items():
                if destination in default_thirdparties and 'unpack' in default_thirdparties[destination]\
                        and 'unpack' not in config:
                    config['unpack'] = default_thirdparties[destination]['unpack']

            inventory['services']['thirdparties'] = upgrade_thirdparties
        else:
            cluster.log.warning('New thirdparties for upgrade procedure is not set in procedure config - default will be used')
    return inventory


def enrich_inventory_apply_defaults(inventory, cluster):
    # if thirdparties is empty, then nothing to do
    if not inventory['services'].get('thirdparties', {}):
        return inventory
    raw_inventory = cluster.raw_inventory

    for destination, config in inventory['services']['thirdparties'].items():

        if isinstance(config, str):
            config = {
                'source': config
            }

        if config.get('source') is None:
            raise Exception('Source not found for thirparty \'%s\'' % destination)

        if config.get('mode') is None:
            config['mode'] = 700

        if config.get('owner') is None:
            config['owner'] = 'root'

        if config.get('group') is not None:
            config['groups'] = [config['group']]
            del config['group']
            if 'master' in config['groups']:
                config['groups'].append('control-plane')

        if config.get('node') is not None:
            config['nodes'] = [config['node']]
            del config['node']

        if config.get('groups') is None and config.get('nodes') is None:
            config['groups'] = ['master', 'worker']

        if config.get('nodes') is not None:
            all_nodes_names = cluster.nodes['all'].get_nodes_names()
            for node_name in config['nodes']:
                if node_name not in all_nodes_names:
                    raise Exception('Unknown node name provided for thirdparty %s. '
                                    'Expected any of %s, but \'%s\' found.'
                                    % (destination, all_nodes_names, node_name))

        # if source is re-defined by user, but "sha1" is not provided,
        # then remove default "sha1", because it may be wrong
        raw_config = raw_inventory.get('services', {}).get('thirdparties', {}).get(destination, {})
        if 'source' in raw_config and 'sha1' not in raw_config and 'sha1' in config:
            del config['sha1']

        inventory['services']['thirdparties'][destination] = config

    # remove "crictl" from thirdparties when docker is used, but ONLY IF it is NOT explicitly specified in cluster.yaml
    cri_name = inventory['services']['cri']['containerRuntime']
    crictl_key = '/usr/bin/crictl.tar.gz'
    if cri_name == "docker" and \
            crictl_key not in cluster.raw_inventory.get('services', {}).get('thirdparties', {}) and \
            crictl_key in inventory['services']['thirdparties']:
        del(inventory['services']['thirdparties'][crictl_key])

    return inventory


def install_thirdparty(cluster: KubernetesCluster, destination, config=None):

    if config is None:
        config = cluster.inventory['services'].get('thirdparties', {}).get(destination)

    if config is None:
        raise Exception('Not possible to install thirdparty %s - not found in configfile' % destination)

    cluster.log.debug("Thirdparty \"%s\" will be installed" % destination)
    is_curl = config['source'][:4] == 'http' and '://' in config['source'][4:8]

    # all commands will be grouped to single run
    remote_commands = ''

    # directory will be created if it is not exists
    destination_directory = '/'.join(destination.split('/')[:-1])
    cluster.log.verbose('Destination directory: %s' % destination_directory)

    common_group = cluster.create_group_from_groups_nodes_names(config.get('groups', []), config.get('nodes', []))

    if cluster.context['initial_procedure'] == 'add_node':
        common_group = common_group.get_new_nodes()

    # ! In the further code there is no error and nothing is missing !
    # Here a long shell command is intentionally constructed and executed at once to speed up work
    # At the same time, in the middle of the construction of the command, a file may suddenly be uploaded and then
    # the command will be executed in two runs instead of single run

    # is destination directory exists?
    remote_commands += 'mkdir -p %s' % destination_directory

    if is_curl:
        cluster.log.verbose('Installation via curl download detected')
        if config.get('sha1') is not None:
            cluster.log.verbose('SHA1 hash is defined, it will be used during installation')
            # if hash equal, then stop further actions immediately! unpack should not be performed too
            remote_commands += ' && FILE_HASH=$(sudo openssl sha1 %s | sed "s/^.* //"); ' \
                               '[ "%s" == "${FILE_HASH}" ] && exit 0 || true ' % (destination, config['sha1'])
        remote_commands += ' && sudo rm -f %s && sudo curl -f -g -L %s -o %s && ' % (destination, config['source'], destination)
    else:
        cluster.log.verbose('Installation via sftp upload detected')
        cluster.log.debug(common_group.sudo(remote_commands))
        remote_commands = ''
        # TODO: Possible use SHA1 from inventory instead of calculating if provided?
        local_path = utils.get_resource_absolute_path(config['source'], script_relative=True)
        binary = bool(config.get('binary', True))
        common_group.put(local_path, destination, sudo=True, binary=binary)

        # TODO: Do not upload local files if they already exists on remote machines

    remote_commands += 'sudo chmod %s %s' % (config['mode'], destination)
    remote_commands += ' && sudo chown %s %s' % (config['owner'], destination)
    remote_commands += ' && sudo ls -la %s' % destination

    if config.get('unpack') is not None:
        cluster.log.verbose('Unpack request detected')

        remote_commands += ' && sudo mkdir -p %s' % config['unpack']

        extension = destination.split('.')[-1]
        if extension == 'zip':
            cluster.log.verbose('Unzip will be used for unpacking')
            remote_commands += ' && sudo unzip %s -d %s' % (destination, config['unpack'])
        else:
            cluster.log.verbose('Tar will be used for unpacking')
            remote_commands += ' && sudo tar -zxf %s -C %s' % (destination, config['unpack'])

        remote_commands += ' && sudo tar -tf %s | xargs -I FILE sudo chmod %s %s/FILE' \
                           % (destination, config['mode'], config['unpack'])
        remote_commands += ' && sudo tar -tf %s | xargs -I FILE sudo chown %s %s/FILE' \
                           % (destination, config['owner'], config['unpack'])
        remote_commands += ' && sudo tar -tf %s | xargs -I FILE sudo ls -la %s/FILE' % (destination, config['unpack'])

    return common_group.sudo(remote_commands)


def install_all_thirparties(group):
    cluster = group.cluster
    log = cluster.log

    if not group.cluster.inventory['services'].get('thirdparties', {}):
        return

    for destination, config in group.cluster.inventory['services']['thirdparties'].items():
        skip_thirdparty = False

        if cluster.context.get("initial_procedure") != "add_node":
            # TODO: speed up algorithm via else/continue/break
            for plugin_name, plugin_configs in group.cluster.inventory['plugins'].items():
                for plugin_procedure in plugin_configs['installation']['procedures']:
                    if plugin_procedure.get('thirdparty') == destination:
                        log.verbose('Thirdparty \'%s\' should be installed with \'%s\' plugin'
                                    % (destination, plugin_name))
                        skip_thirdparty = True

        if skip_thirdparty:
            log.verbose('Thirdparty %s installation delayed' % destination)
        else:
            res = install_thirdparty(group.cluster, destination, config)
            log.debug(res)
