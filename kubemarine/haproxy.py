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
import time
from typing import List, Optional

from jinja2 import Template

from kubemarine import system, packages
from kubemarine.core import utils, static
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.group import (
    NodeGroup, RunnersGroupResult, NodeConfig, DeferredGroup, RunResult, AbstractGroup, CollectorCallback
)

ERROR_VRRP_IS_NOT_CONFIGURED = \
    'Balancer is combined with other role, but there is no VRRP IP configured for node \'%s\'.'

ERROR_NO_BOUND_VRRP_CONFIGURED_MNTC = \
    'No suitable bindings found for haproxy in maintenance mode for node \'%s\'. ' \
    'Balancer is combined with other role and has no configured VRRP IP ' \
    'that is not marked with maintenance-type: "not bind"'


def is_maintenance_mode(cluster: KubernetesCluster) -> bool:
    return bool(cluster.raw_inventory.get('services', {}).get('loadbalancer', {})
                .get('haproxy', {}).get('maintenance_mode', False))


def _get_associations_for_node(node: AbstractGroup[RunResult]) -> dict:
    return node.cluster.get_associations_for_node(node.get_host(), 'haproxy')


def is_vrrp_not_bind(vrrp_item: dict) -> bool:
    maintenance_type: str = vrrp_item.get('params', {}).get('maintenance-type', '')
    return maintenance_type == 'not bind'


def _get_bindings(inventory: dict, node: NodeConfig, *, maintenance: bool) -> List[str]:
    # bindings list for common config and maintenance should be different

    is_combined = len([role for role in node['roles'] if role != 'add_node']) > 1

    if not maintenance and not is_combined:
        return ["0.0.0.0", '::']

    # If we have combination of balancer-control-plane / balancer-worker or if haproxy is in maintenance mode,
    # VRRP IP should be defined for the given balancer.
    # In maintenance mode it should also be not "not bind".

    bindings = []
    for item in inventory['vrrp_ips']:
        # skip IPs with type 'not bind' in maintenance mode
        if maintenance and is_vrrp_not_bind(item):
            continue
        for record in item['hosts']:
            if record['name'] == node['name']:
                bindings.append(item['ip'])

    if not is_combined:
        # In maintenance mode and if balancer is not combined with some other role,
        # we can listen also own internal address of the balancer
        bindings.append(node['internal_address'])

    # remove duplicates
    return list(set(bindings))


def enrich_inventory(inventory: dict, cluster: KubernetesCluster) -> dict:

    for node in inventory["nodes"]:
        if 'balancer' not in node['roles'] or 'remove_node' in node['roles']:
            continue

        regular_bindings = _get_bindings(inventory, node, maintenance=False)
        if not regular_bindings:
            raise Exception(ERROR_VRRP_IS_NOT_CONFIGURED % node['name'])

        is_mntc_mode = is_maintenance_mode(cluster)
        mntc_bindings = _get_bindings(inventory, node, maintenance=True)
        if is_mntc_mode and not mntc_bindings:
            raise Exception(ERROR_NO_BOUND_VRRP_CONFIGURED_MNTC % node["name"])

        not_bind = sum(1 for item in inventory["vrrp_ips"] if is_vrrp_not_bind(item))
        if bool(not_bind) != is_mntc_mode:
            raise Exception("Haproxy maintenance mode should be used when and only when "
                            "there is at least one VRRP IP with 'maintenance-type: not bind'")

        group = cluster.make_group([node['connect_to']])
        os_family = group.get_nodes_os()
        if is_mntc_mode and os_family not in ('unknown', 'unsupported'):
            config_location = _get_associations_for_node(group)['config_location']
            mntc_config_location = inventory['services']['loadbalancer']['haproxy']['mntc_config_location']
            # if 'maintenance_mode' is True then maintenance config and default config must be stored in different files'
            if mntc_config_location == config_location:
                raise Exception("Maintenance mode configuration file must be different with default configuration file")

    return inventory


def get_config_path(group: NodeGroup) -> RunnersGroupResult:
    collector = CollectorCallback(group.cluster)
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            package_associations = _get_associations_for_node(node)
            cmd = f"systemctl show -p MainPID {package_associations['service_name']} " \
                  f"| cut -d '=' -f2 " \
                  f"| xargs -I PID sudo cat /proc/PID/environ " \
                  f"| tr '\\0' '\\n' | grep CONFIG | cut -d \"=\" -f2 | tr -d '\\n'"
            node.sudo(cmd, callback=collector)

    return collector.result


def install(group: NodeGroup) -> RunnersGroupResult:
    cluster = group.cluster
    defer = group.new_defer()
    collector = CollectorCallback(cluster)
    for node in defer.get_ordered_members_list():
        package_associations = _get_associations_for_node(node)
        node.sudo("%s -v" % package_associations['executable_name'], warn=True, callback=collector)

    defer.flush()

    if not collector.result.is_any_failed():
        cluster.log.debug("HAProxy already installed, nothing to install")
    else:
        collector = CollectorCallback(cluster)
        for node in defer.get_ordered_members_list():
            package_associations = _get_associations_for_node(node)
            packages.install(node, include=package_associations['package_name'], callback=collector)

        defer.flush()

    for node in defer.get_ordered_members_list():
        package_associations = _get_associations_for_node(node)
        service_name = package_associations['service_name']
        patch_path = "./resources/drop_ins/haproxy.conf"
        node.call(system.patch_systemd_service, service_name=service_name, patch_source=patch_path)
        enable(node)

    defer.flush()
    return collector.result


def uninstall(group: NodeGroup) -> RunnersGroupResult:
    return packages.remove(group, include=['haproxy', 'rh-haproxy18'])


def restart(group: NodeGroup) -> None:
    cluster: KubernetesCluster = group.cluster
    cluster.log.debug("Restarting haproxy in all group...")
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = _get_associations_for_node(node)['service_name']
            system.restart_service(node, name=service_name)

    cluster.log.debug("Sleep while haproxy comes-up...")
    time.sleep(static.GLOBALS['haproxy']['restart_wait'])


def disable(group: NodeGroup) -> None:
    with group.new_executor() as exe:
        for node in exe.group.get_ordered_members_list():
            service_name = _get_associations_for_node(node)['service_name']
            system.disable_service(node, name=service_name)


def enable(node: DeferredGroup) -> None:
    # currently it is invoked only for single node
    service_name = _get_associations_for_node(node)['service_name']
    system.enable_service(node, name=service_name, now=True)


def get_config(cluster: KubernetesCluster, node: NodeConfig, maintenance: bool = False) -> str:
    future_nodes = cluster.nodes['all'].get_final_nodes().get_ordered_members_configs_list()

    inventory = cluster.inventory
    bindings = _get_bindings(inventory, node, maintenance=maintenance)

    config_options: dict = inventory['services']['loadbalancer']['haproxy']
    config_string: Optional[str] = config_options.get('config')
    if config_string is not None:
        return config_string

    target_ports: dict = inventory['services']['loadbalancer']['target_ports']

    # todo support custom template for maintenance mode
    if not maintenance and config_options.get('config_file'):
        config_source = utils.read_external(config_options['config_file'])
    else:
        config_source = utils.read_internal('templates/haproxy.cfg.j2')

    return Template(config_source).render(nodes=future_nodes,
                                          bindings=bindings,
                                          config_options=config_options,
                                          target_ports=target_ports)


def configure(group: DeferredGroup) -> None:
    cluster: KubernetesCluster = group.cluster

    for node in group.get_ordered_members_list():
        node_config = node.get_config()
        node_name = node.get_node_name()
        package_associations = _get_associations_for_node(node)

        cluster.log.debug("\nConfiguring haproxy on \'%s\'..." % node_name)
        config = get_config(cluster, node_config)
        utils.dump_file(cluster, config, 'haproxy_%s.cfg' % node_name)
        node.put(io.StringIO(config), package_associations['config_location'], backup=True, sudo=True, mkdir=True)

        # add maintenance config to balancer if 'maintenance_mode' is True
        if is_maintenance_mode(cluster):
            mntc_config_location = cluster.inventory['services']['loadbalancer']['haproxy']['mntc_config_location']
            cluster.log.debug("\nConfiguring haproxy for maintenance on \'%s\'..." % node_name)
            mntc_config = get_config(cluster, node_config, True)
            utils.dump_file(cluster, mntc_config, 'haproxy_mntc_%s.cfg' % node_name)
            node.put(io.StringIO(mntc_config), mntc_config_location, backup=True, sudo=True, mkdir=True)


def override_haproxy18(group: DeferredGroup) -> None:
    rhel_nodes = group.get_subgroup_with_os('rhel')
    if rhel_nodes.is_empty():
        group.cluster.log.debug('Haproxy18 override is not required')
        return

    # Any node in group has rhel OS family, so association can be fetched from any node.
    any_host = rhel_nodes.get_first_member().get_host()
    package_associations = group.cluster.get_associations_for_node(any_host, 'haproxy')
    # TODO: Do not replace the whole file, replace only parameter
    group.put(
        io.StringIO("CONFIG=%s\n" % package_associations['config_location']),
        '/etc/sysconfig/%s' % package_associations['service_name'],
        backup=True, sudo=True)
