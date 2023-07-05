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
import random
import time
from typing import Optional, List

from jinja2 import Template

from kubemarine import system, packages
from kubemarine.core import utils, static
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import NodeGroup, NodeConfig, RunnersGroupResult


def autodetect_interface(cluster: KubernetesCluster, name: str) -> Optional[str]:
    for node in cluster.inventory['nodes']:
        if node['name'] == name:
            address = cluster.get_access_address_from_node(node)
            interface: str = cluster.context['nodes'].get(address, {})['active_interface']
            if interface:
                return interface
    if cluster.context['initial_procedure'] == 'remove_node':
        for node_to_remove in cluster.procedure_inventory['nodes']:
            if node_to_remove['name'] == name:
                return None
    raise Exception('Failed to autodetect active interface for %s' % name)


def enrich_inventory_apply_defaults(inventory: dict, cluster: KubernetesCluster) -> dict:
    # if vrrp_ips is empty, then nothing to do
    if not inventory['vrrp_ips']:
        return inventory

    default_names = get_default_node_names(inventory)

    cluster.log.verbose("Detected default keepalived hosts: %s" % default_names)
    if not default_names:
        cluster.log.verbose("WARNING: Default keepalived hosts are empty: something can go wrong!")

    # iterate over each vrrp_ips item and check if any hosts defined to be used in it
    for i, item in enumerate(inventory['vrrp_ips']):

        if isinstance(item, str):
            inventory['vrrp_ips'][i] = item = {
                'ip': item
            }

        # is router_id defined?
        if item.get('router_id') is None:
            # is there ipv6?
            if ':' in item['ip']:
                item['router_id'] = item['ip'].split(':').pop()
                if item['router_id'] == '':
                    item['router_id'] = '0'
                # in adress with long last octet e.g. "765d" it is necessary to use only last "5d" and convert it from hex to int
                item['router_id'] = str(int(item['router_id'][-2:], 16))
            else:
                item['router_id'] = item['ip'].split('.').pop()

        # is id defined?
        if item.get('id') is None:
            # label max size is 15, then 15 - 5 (size from string "vip_") = 10 symbols we can use
            source_string = item.get('interface', 'auto') + item['ip']
            label_size = cluster.globals['keepalived']['defaults']['label_size']
            item['id'] = hashlib.md5(source_string.encode('utf-8')).hexdigest()[:label_size]

        # is password defined?
        if item.get('password') is None:
            password_size = cluster.globals['keepalived']['defaults']['password_size']
            item['password'] = ("%032x" % random.getrandbits(128))[:password_size]

        # if nothing defined then use default names
        if item.get('hosts') is None:
            # is there default names found?
            if not default_names:
                raise Exception('Section #%s in vrrp_ips has no hosts, but default names can\'t be found.' % i)
            # ok, default names found, and can be used
            inventory['vrrp_ips'][i]['hosts'] = default_names

        for j, record in enumerate(item['hosts']):
            if isinstance(record, str):
                item['hosts'][j] = {
                    'name': record
                }
            if not item['hosts'][j].get('priority'):
                item['hosts'][j]['priority'] = cluster.globals['keepalived']['defaults']['priority']['max_value'] - \
                                               (j + cluster.globals['keepalived']['defaults']['priority']['step'])
            if not item['hosts'][j].get('interface') and item.get('interface'):
                item['hosts'][j]['interface'] = item['interface']
            if item['hosts'][j].get('interface', 'auto') == 'auto':
                item['hosts'][j]['interface'] = autodetect_interface(cluster, item['hosts'][j]['name'])

    return inventory


def get_default_node_names(inventory: dict) -> List[str]:
    default_names = []

    # well, vrrp_ips is not empty, let's find balancers defined in config-file
    for i, node in enumerate(inventory['nodes']):
        if 'balancer' in node['roles']:
            default_names.append(node['name'])

    # just in case, we remove duplicates
    return list(set(default_names))


def enrich_inventory_calculate_nodegroup(inventory: dict, cluster: KubernetesCluster) -> dict:
    # if vrrp_ips is empty, then nothing to do
    if not inventory['vrrp_ips']:
        return inventory

    # Calculate group, where keepalived should be installed:
    names = []

    for i, item in enumerate(cluster.inventory['vrrp_ips']):
        for record in item['hosts']:
            names.append(record['name'])

    # it is important to remove duplicates
    names = list(set(names))

    # create new group where keepalived will be installed
    cluster.nodes['keepalived'] = cluster.nodes['all'].new_group(apply_filter={
        'name': names
    })

    # create new role
    cluster.roles.append('keepalived')

    # fill in ips
    cluster.ips['keepalived'] = cluster.nodes['keepalived'].get_hosts()

    return inventory


def install(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    # todo why check and try to install all keepalives but finally filter out only new nodes?
    group = group.get_new_nodes_or_self()
    # todo consider probably different associations for nodes with different OS families
    any_host = group.get_first_member().get_host()
    package_associations = cluster.get_associations_for_node(any_host, 'keepalived')

    keepalived_version = group.sudo("%s -v" % package_associations['executable_name'], warn=True)
    keepalived_installed = True

    for connection, result in keepalived_version.items():
        if result.exited != 0:
            keepalived_installed = False

    if keepalived_installed:
        log.debug("Keepalived already installed, nothing to install")
        installation_result = keepalived_version
    else:
        installation_result = packages.install(group, include=package_associations['package_name'])

    service_name = package_associations['service_name']
    patch_path = "./resources/drop_ins/keepalived.conf"
    group.call(system.patch_systemd_service, service_name=service_name, patch_source=patch_path)
    group.call(install_haproxy_check_script)
    enable(group)

    return installation_result


def install_haproxy_check_script(group: NodeGroup) -> None:
    script = utils.read_internal("./resources/scripts/check_haproxy.sh")
    group.put(io.StringIO(script), "/usr/local/bin/check_haproxy.sh", sudo=True)
    group.sudo("chmod +x /usr/local/bin/check_haproxy.sh")


def uninstall(group: NodeGroup) -> RunnersGroupResult:
    return packages.remove(group, include='keepalived')


def restart(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    cluster.log.debug("Restarting keepalived in all group...")
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'service_name')
            system.restart_service(node, name=service_name)

    cluster.log.debug("Sleep while keepalived comes-up...")
    time.sleep(static.GLOBALS['keepalived']['restart_wait'])


def enable(group: NodeGroup) -> None:
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = exe.cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'service_name')
            system.enable_service(node, name=service_name, now=True)


def disable(group: NodeGroup) -> None:
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = exe.cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'service_name')
            system.disable_service(node, name=service_name)


def generate_config(inventory: dict, node: NodeConfig) -> str:
    config = ''

    for i, item in enumerate(inventory['vrrp_ips']):

        if i > 0:
            # this is required for double newline in config, but avoid double newline in the end of file
            config += "\n"

        ips = {
            'source': node['internal_address'],
            'peers': []
        }

        priority = 100
        interface = 'eth0'
        # todo Probably skip the VRRP if it not defined for this node?
        #  Currently behaviour does not correspond to documentation.
        for record in item['hosts']:
            if record['name'] == node['name']:
                priority = record['priority']
                interface = record['interface']

        for i_node in inventory['nodes']:
            for record in item['hosts']:
                if i_node['name'] == record['name'] and i_node['internal_address'] != ips['source']:
                    ips['peers'].append(i_node['internal_address'])

        config_source = utils.read_internal('templates/keepalived.conf.j2')
        config += Template(config_source).render(inventory=inventory, item=item, node=node,
                                                 interface=interface,
                                                 priority=priority, **ips) + "\n"

    return config


def configure(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    log = cluster.log

    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            node_name = node.get_node_name()
            log.debug("Configuring keepalived on '%s'..." % node_name)

            package_associations = cluster.get_associations_for_node(node.get_host(), 'keepalived')
            configs_directory = '/'.join(package_associations['config_location'].split('/')[:-1])

            exe.group.sudo('mkdir -p %s' % configs_directory)

            config = generate_config(cluster.inventory, node.get_config())
            utils.dump_file(cluster, config, 'keepalived_%s.conf' % node_name)

            node.put(io.StringIO(config), package_associations['config_location'], sudo=True)

    log.debug(group.sudo('ls -la %s' % package_associations['config_location']))

    restart(group)

    return group.sudo('systemctl status %s' % package_associations['service_name'], warn=True)
