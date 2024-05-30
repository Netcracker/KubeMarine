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
from kubemarine.core.cluster import KubernetesCluster, EnrichmentStage, enrichment
from kubemarine.core.group import NodeGroup, NodeConfig, RunnersGroupResult, CollectorCallback, DeferredGroup


def autodetect_interface(cluster: KubernetesCluster, name: str) -> str:
    address = cluster.nodes['all'].get_member_by_name(name).get_host()
    interface: str = cluster.nodes_context.get(address, {}).get('active_interface')
    # If undefined, still return it. The error about inaccessible nodes will be raised later.
    if interface:
        return interface

    raise Exception('Failed to autodetect active interface for %s' % name)


@enrichment(EnrichmentStage.PROCEDURE, procedures=['add_node'])
def enrich_add_node_vrrp_ips(_: KubernetesCluster) -> None:
    # If "vrrp_ips" section is ever supported when adding node,
    # It will be necessary to more accurately install and reconfigure the keepalived on existing nodes.

    # if "vrrp_ips" in cluster.procedure_inventory:
    #     utils.merge_vrrp_ips(cluster.procedure_inventory, inventory)
    pass


@enrichment(EnrichmentStage.PROCEDURE, procedures=['remove_node'])
def enrich_remove_node_vrrp_ips(_: KubernetesCluster) -> None:
    # Do not remove VRRP IPs and do not change their assigned hosts.
    # If the assigned host does not exist or is not a balancer, it will be just skipped.
    pass


@enrichment(EnrichmentStage.FULL)
def enrich_inventory_apply_defaults(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory

    # if vrrp_ips is empty, then nothing to do
    if not inventory['vrrp_ips']:
        return

    logger = cluster.log

    balancers = get_all_balancer_names(inventory)

    logger.verbose("Detected default keepalived hosts: %s" % balancers)
    if not balancers:
        logger.warning("VRRP IPs are specified, but there are no balancers. Keepalived will not be configured.")

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
            # Assign default list of all the balancer names. It can be an empty list.
            item['hosts'] = list(balancers)

        for j, record in enumerate(item['hosts']):
            if isinstance(record, str):
                item['hosts'][j] = record = {
                    'name': record
                }
            if record['name'] not in balancers:
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


def get_all_balancer_names(inventory: dict) -> List[str]:
    default_names = []

    # well, vrrp_ips is not empty, let's find balancers defined in config-file
    for node in inventory['nodes']:
        if 'balancer' in node['roles']:
            default_names.append(node['name'])

    return default_names


@enrichment(EnrichmentStage.FULL)
def enrich_inventory_calculate_nodegroup(cluster: KubernetesCluster) -> None:
    inventory = cluster.inventory

    # if vrrp_ips is empty, then nothing to do
    if not inventory['vrrp_ips']:
        return

    # Calculate group, where keepalived should be installed:
    names = []

    for item in inventory['vrrp_ips']:
        for record in item['hosts']:
            names.append(record['name'])

    # Create new group from balancers with Keepalived (to be) on them.
    keepalived_group = cluster.make_group_from_roles(['balancer']).new_group(apply_filter={
        'name': names
    })

    if not keepalived_group.is_empty():
        cluster.nodes['keepalived'] = keepalived_group


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
            packages.install(node, include=package_name, pty=True, callback=collector)

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
    config_options: dict = cluster.inventory['services']['loadbalancer']['keepalived']
    config_string: Optional[str] = config_options.get('config')
    if config_string is not None:
        return config_string

    vrrps_ips = []
    keepalived_nodes = cluster.nodes['keepalived'].get_ordered_members_configs_list()
    for item in cluster.inventory['vrrp_ips']:
        host = next((record for record in item['hosts'] if record['name'] == node['name']), None)
        if not host:
            # This VRRP IP should not be configured on this node.
            # There is still at least one VRRP IP to configure on this node
            # due to the way how 'keepalived' group is calculated.
            continue
        vrrps_ips.append({
            'id': item['id'],
            'router_id': item['router_id'],
            'ip': item['ip'],
            'password': item['password'],
            'interface': host['interface'],
            'priority': host['priority'],
            'source': node['internal_address'],
            'peers': [
                i_node['internal_address'] for i_node in keepalived_nodes
                if any(i_node['name'] == record['name'] and i_node['internal_address'] != node['internal_address']
                       for record in item['hosts'])
            ]
        })

    if config_options.get('config_file'):
        config_source = utils.read_external(config_options['config_file'])
    else:
        config_source = utils.read_internal('templates/keepalived.conf.j2')
    config = Template(config_source).render(vrrp_ips=vrrps_ips, globals=config_options['global'])

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
