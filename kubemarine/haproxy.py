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

from jinja2 import Template

from kubemarine import system, packages
from kubemarine.core import utils
from kubemarine.core.cluster import KubernetesCluster
from kubemarine.core.executor import RemoteExecutor
from kubemarine.core.group import NodeGroupResult, NodeGroup

ERROR_VRRP_IS_NOT_CONFIGURED = "Balancer is combined with other role, but VRRP IP is not configured."


def is_maintenance_mode(cluster: KubernetesCluster) -> bool:
    return bool(cluster.raw_inventory.get('services', {}).get('loadbalancer', {})
                .get('haproxy', {}).get('maintenance_mode', False))


def get_associations_for_node(node: dict) -> dict:
    conn: NodeGroup = node['connection']
    return conn.cluster.get_associations_for_node(node['connect_to'])['haproxy']


def enrich_inventory(inventory, cluster):

    for node in inventory["nodes"]:
        # todo what if balancer is removed? It will have roles=['balancer', 'remove_node']
        if 'balancer' in node['roles'] and len(node['roles']) > 1:

            # ok, seems we have combination of balancer-control-plane / balancer-worker
            # in that case VRRP IP should be defined

            # let's check vrrp ip section is defined
            if not inventory["vrrp_ips"]:
                raise Exception(ERROR_VRRP_IS_NOT_CONFIGURED)

            found = False
            # let's check we have current balancer to be defined in vrrp ip hosts:
            for item in inventory["vrrp_ips"]:
                for record in item['hosts']:
                    if record['name'] == node['name']:
                        # seems there is at least 1 vrrp ip for current balancer
                        found = True

            if not found:
                raise Exception('Balancer is combined with other role, but there is no any VRRP IP configured for '
                                'node \'%s\'.' % node['name'])
        if 'balancer' in node['roles']:
            not_bind = sum(1 for item in inventory["vrrp_ips"]
                           if isinstance(item, dict)
                           and item.get('params', {}).get('maintenance-type', False) == 'not bind')
            is_mntc_mode = is_maintenance_mode(cluster)
            if bool(not_bind) != is_mntc_mode:
                raise Exception("Haproxy maintenance mode should be used when and only when "
                                "there is at least one VRRP IP with 'maintenance-type: not bind'")

            if is_mntc_mode:
                config_location = get_associations_for_node(node)['config_location']
                mntc_config_location = inventory['services']['loadbalancer']['haproxy']['mntc_config_location']
                # if 'maintenance_mode' is True then must be at least one IP without 'maintenance-type: not bind'
                if not_bind == len(inventory["vrrp_ips"]):
                    raise Exception("Balancer maintenance mode needes at least one VRRP IP without 'maintenance-type: not bind'")
                # if 'maintenance_mode' is True then maintenance config and default config must be stored in different files'
                if mntc_config_location == config_location:
                    raise Exception("Maintenance mode configuration file must be different with default configuration file")

    return inventory


def get_config_path(group: NodeGroup) -> NodeGroupResult:
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            package_associations = get_associations_for_node(node)
            cmd = f"systemctl show -p MainPID {package_associations['service_name']} " \
                  f"| cut -d '=' -f2 " \
                  f"| xargs -I PID sudo cat /proc/PID/environ " \
                  f"| tr '\\0' '\\n' | grep CONFIG | cut -d \"=\" -f2 | tr -d '\\n'"
            node['connection'].sudo(cmd)

    return exe.get_merged_result()


def install(group):
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            package_associations = get_associations_for_node(node)
            node['connection'].sudo("%s -v" % package_associations['executable_name'], warn=True)

    haproxy_installed = True
    for host, host_results in exe.get_last_results().items():
        if list(host_results.values())[0].exited != 0:
            haproxy_installed = False

    if haproxy_installed:
        # TODO: Add Haproxy version output from previous command to method results
        group.cluster.log.debug("HAProxy already installed, nothing to install")
    else:
        with RemoteExecutor(group.cluster) as exe:
            for node in group.get_ordered_members_list(provide_node_configs=True):
                package_associations = get_associations_for_node(node)
                packages.install(node["connection"], include=package_associations['package_name'])

    service_name = package_associations['service_name']
    patch_path = utils.get_resource_absolute_path("./resources/drop_ins/haproxy.conf", script_relative=True)
    group.call(system.patch_systemd_service, service_name=service_name, patch_source=patch_path)
    enable(group)
    return exe.get_last_results_str()


def uninstall(group):
    return packages.remove(group, include=['haproxy', 'rh-haproxy18'])


def restart(group):
    for node in group.get_ordered_members_list(provide_node_configs=True):
        service_name = get_associations_for_node(node)['service_name']
        system.restart_service(node['connection'], name=service_name)
    RemoteExecutor(group.cluster).flush()
    group.cluster.log.debug("Sleep while haproxy comes-up...")
    time.sleep(group.cluster.globals['haproxy']['restart_wait'])
    return


def disable(group):
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            service_name = get_associations_for_node(node)['service_name']
            system.disable_service(node['connection'], name=service_name)


def enable(group):
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            service_name = get_associations_for_node(node)['service_name']
            system.enable_service(node['connection'], name=service_name,
                                  now=True)


def get_config(cluster, node, future_nodes, maintenance=False):

    bindings = []
    # bindings list for common config and maintenance should be different
    if maintenance:
        for item in cluster.inventory['vrrp_ips']:
            if isinstance(item, dict):
                if not item.get('params', {}).get('maintenance-type', False):
                    # add unmarked IPs
                    bindings.append(item['ip'])
                elif item.get('params', {}).get('maintenance-type', False) != 'not bind':
                    # add IPs with type different from 'not bind'
                    # that is the temporary solution
                    bindings.append(item['ip'])
            elif isinstance(item, str):
                    # add unmarked IPs
                    bindings.append(item)
            else:
                raise Exception("Error in VRRP IPs description") 
    else:
        if len(node['roles']) == 1 or not cluster.inventory['vrrp_ips']:
            bindings.append("0.0.0.0")
            bindings.append("::")
        else:
            for item in cluster.inventory['vrrp_ips']:
                for record in item['hosts']:
                    if record['name'] == node['name']:
                        bindings.append(item['ip'])

    # remove duplicates
    bindings = list(set(bindings))

    if cluster.inventory['services'].get('loadbalancer', {}).get('haproxy', {}).get('config'):
        return cluster.inventory['services']['loadbalancer']['haproxy']['config']

    config_file = utils.get_resource_absolute_path('templates/haproxy.cfg.j2', script_relative=True)
    # todo support custom template for maintenance mode
    if not maintenance and cluster.inventory['services'].get('loadbalancer', {}).get('haproxy', {}).get('config_file'):
        config_file = utils.get_resource_absolute_path(
            cluster.inventory['services']['loadbalancer']['haproxy']['config_file'],
            script_relative=False)

    config_source = open(config_file).read()

    config_options = cluster.inventory['services'].get('loadbalancer', {}).get('haproxy', {})

    return Template(config_source).render(nodes=future_nodes,
                                          bindings=bindings,
                                          config_options=config_options)


def configure(group: NodeGroup):
    cluster = group.cluster
    all_nodes_configs = cluster.nodes['all'].get_final_nodes().get_ordered_members_list(provide_node_configs=True)

    for node in group.get_ordered_members_list(provide_node_configs=True):
        package_associations = get_associations_for_node(node)
        configs_directory = '/'.join(package_associations['config_location'].split('/')[:-1])

        cluster.log.debug("\nConfiguring haproxy on \'%s\'..." % node['name'])
        config = get_config(cluster, node, all_nodes_configs)
        utils.dump_file(cluster, config, 'haproxy_%s.cfg' % node['name'])
        node['connection'].sudo('mkdir -p %s' % configs_directory)
        node['connection'].put(io.StringIO(config), package_associations['config_location'], backup=True, sudo=True)
        node['connection'].sudo('ls -la %s' % package_associations['config_location'])

        # add maintenance config to balancer if 'maintenance_mode' is True
        if is_maintenance_mode(cluster):
            mntc_config_location = cluster.inventory['services']['loadbalancer']['haproxy']['mntc_config_location']
            cluster.log.debug("\nConfiguring haproxy for maintenance on \'%s\'..." % node['name'])
            mntc_config = get_config(cluster, node, all_nodes_configs, True)
            utils.dump_file(cluster, mntc_config, 'haproxy_mntc_%s.cfg' % node['name'])
            node['connection'].sudo('mkdir -p %s' % configs_directory)
            node['connection'].put(io.StringIO(mntc_config), mntc_config_location, backup=True, sudo=True)
            node['connection'].sudo('ls -la %s' % mntc_config_location)


def override_haproxy18(group):
    rhel_nodes = group.get_subgroup_with_os('rhel')
    if rhel_nodes.is_empty():
        group.cluster.log.debug('Haproxy18 override is not required')
        return
    package_associations = group.cluster.get_associations_for_os('rhel')['haproxy']
    # TODO: Do not replace the whole file, replace only parameter
    return group.put(io.StringIO("CONFIG=%s\n" % package_associations['config_location']),
                     '/etc/sysconfig/%s' % package_associations['service_name'], backup=True, sudo=True)
