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
from kubemarine.core.group import NodeGroup, NodeConfig, RunnersGroupResult, CollectorCallback, DeferredGroup


def autodetect_interface(cluster: KubernetesCluster, name: str) -> str:
    node = cluster.get_node_by_name(name)
    if node is not None:
        address = cluster.get_access_address_from_node(node)
        interface: Optional[str] = cluster.context['nodes'].get(address, {}).get('active_interface')
        if interface is not None:
            return interface

    raise Exception('Failed to autodetect active interface for %s' % name)


def enrich_inventory_apply_defaults(inventory: dict, cluster: KubernetesCluster) -> dict:
    # if vrrp_ips is empty, then nothing to do
    if not inventory['vrrp_ips']:
        return inventory

    logger = cluster.log

    initial_balancers = get_all_balancer_names(inventory, final=False)
    final_balancers = get_all_balancer_names(inventory, final=True)

    logger.verbose("Detected default keepalived hosts: %s" % initial_balancers)
    if not final_balancers:
        logger.warning("VRRP IPs are specified, but there are no final balancers. Keepalived will not be configured.")

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
        default_hosts = False
        if item.get('hosts') is None:
            # Assign default list of all the balancer names. It can be an empty list.
            # Assigning of initial balancers is necessary to property calculate 'keepalived' NodeGroup.
            item['hosts'] = list(initial_balancers)
            default_hosts = True

        for j, record in enumerate(item['hosts']):
            if isinstance(record, str):
                item['hosts'][j] = record = {
                    'name': record
                }
            if record['name'] not in final_balancers:
                # If default hosts are assigned,
                # the temporarily assigned host to be removed will be removed later from finalized inventory.
                # See remove_node.remove_node_finalize_inventory().
                if not default_hosts:
                    cluster.log.warning(f"Host {record['name']!r} for VRRP IP {item['ip']} is not among the balancers. "
                                        f"This VRRP IP will not be installed on this host.")
                continue
            if not record.get('priority'):
                priority_settings = static.GLOBALS['keepalived']['defaults']['priority']
                record['priority'] = priority_settings['max_value'] - (j + priority_settings['step'])
            if not record.get('interface') and item.get('interface'):
                record['interface'] = item['interface']
            if record.get('interface', 'auto') == 'auto':
                record['interface'] = autodetect_interface(cluster, record['name'])

    return inventory


def get_all_balancer_names(inventory: dict, *, final: bool = True) -> List[str]:
    default_names = []

    # well, vrrp_ips is not empty, let's find balancers defined in config-file
    for i, node in enumerate(inventory['nodes']):
        if 'balancer' in node['roles'] and (not final or 'remove_node' not in node['roles']):
            default_names.append(node['name'])

    return default_names


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

    # Create new group from balancers with Keepalived (to be) on them. This includes nodes to be removed.
    cluster.nodes['keepalived'] = cluster.make_group_from_roles(['balancer']).new_group(apply_filter={
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

    defer = group.new_defer()
    collector = CollectorCallback(cluster)
    for node in defer.get_ordered_members_list():
        executable_name = cluster.get_package_association_for_node(
            node.get_host(), 'keepalived', 'executable_name')
        node.sudo("%s -v" % executable_name, warn=True, callback=collector)

    defer.flush()

    if not collector.result.is_any_failed():
        log.debug("Keepalived already installed, nothing to install")
    else:
        collector = CollectorCallback(cluster)
        for node in defer.get_ordered_members_list():
            package_name = cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'package_name')
            packages.install(node, include=package_name, callback=collector)

        defer.flush()

    for node in defer.get_ordered_members_list():
        service_name = cluster.get_package_association_for_node(
            node.get_host(), 'keepalived', 'service_name')
        patch_path = "./resources/drop_ins/keepalived.conf"
        node.call(system.patch_systemd_service, service_name=service_name, patch_source=patch_path)
        node.call(install_haproxy_check_script)
        enable(node)

    defer.flush()
    return collector.result


def install_haproxy_check_script(group: DeferredGroup) -> None:
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


def enable(node: DeferredGroup) -> None:
    # currently it is invoked only for single node
    service_name = node.cluster.get_package_association_for_node(
        node.get_host(), 'keepalived', 'service_name')
    system.enable_service(node, name=service_name, now=True)


def disable(group: NodeGroup) -> None:
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = exe.cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'service_name')
            system.disable_service(node, name=service_name)


def generate_config(cluster: KubernetesCluster, node: NodeConfig) -> str:
    config = ''

    inventory = cluster.inventory
    for i, item in enumerate(inventory['vrrp_ips']):

        if i > 0:
            # this is required for double newline in config, but avoid double newline in the end of file
            config += "\n"

        ips = {
            'source': node['internal_address'],
            'peers': []
        }

        for record in item['hosts']:
            if record['name'] == node['name']:
                priority = record['priority']
                interface = record['interface']
                break
        else:
            # This VRRP IP should not be configured on this node.
            # There is still at least one VRRP IP to configure on this node
            # due to the way how 'keepalived' group is calculated.
            continue

        for i_node in cluster.nodes['keepalived'].get_final_nodes().get_ordered_members_configs_list():
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

    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            node_name = node.get_node_name()
            log.debug("Configuring keepalived on '%s'..." % node_name)

            config_location = cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'config_location')

            config = generate_config(cluster, node.get_config())
            utils.dump_file(cluster, config, 'keepalived_%s.conf' % node_name)

            node.put(io.StringIO(config), config_location, sudo=True, mkdir=True)
            node.sudo('ls -la %s' % config_location, callback=collector)

    log.debug(collector.result)

    restart(group)

    return status(group)


def status(group: NodeGroup) -> RunnersGroupResult:
    cluster: KubernetesCluster = group.cluster
    collector = CollectorCallback(cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = cluster.get_package_association_for_node(
                node.get_host(), 'keepalived', 'service_name')
            system.service_status(node, name=service_name, callback=collector)

    return collector.result
