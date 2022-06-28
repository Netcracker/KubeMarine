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
from kubemarine.core.executor import RemoteExecutor

ERROR_VRRP_IS_NOT_CONFIGURED = "Balancer is combined with other role, but VRRP IP is not configured."


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

    return inventory


def install(group):
    with RemoteExecutor(group.cluster) as exe:
        for node in group.get_ordered_members_list(provide_node_configs=True):
            package_associations = group.cluster.get_associations_for_node(node['connect_to'])['haproxy']
            group.sudo("%s -v" % package_associations['executable_name'], warn=True)

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
                package_associations = group.cluster.get_associations_for_node(node['connect_to'])['haproxy']
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
        service_name = group.cluster.get_associations_for_node(node['connect_to'])['haproxy']['service_name']
        system.restart_service(node['connection'], name=service_name)
    RemoteExecutor(group.cluster).flush()
    group.cluster.log.debug("Sleep while haproxy comes-up...")
    time.sleep(group.cluster.globals['haproxy']['restart_wait'])
    return


def disable(group):
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'])
            system.disable_service(node['connection'], name=os_specific_associations['haproxy']['service_name'])


def enable(group):
    with RemoteExecutor(group.cluster):
        for node in group.get_ordered_members_list(provide_node_configs=True):
            os_specific_associations = group.cluster.get_associations_for_node(node['connect_to'])
            system.enable_service(node['connection'], name=os_specific_associations['haproxy']['service_name'],
                                  now=True)


def get_config(cluster, node, future_nodes):

    bindings = []
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
    if cluster.inventory['services'].get('loadbalancer', {}).get('haproxy', {}).get('config_file'):
        config_file = utils.get_resource_absolute_path(
            cluster.inventory['services']['loadbalancer']['haproxy']['config_file'],
            script_relative=False)

    config_source = open(config_file).read()

    config_options = cluster.inventory['services'].get('loadbalancer', {}).get('haproxy', {})

    return Template(config_source).render(nodes=future_nodes,
                                          bindings=bindings,
                                          config_options=config_options)


def configure(group):
    all_nodes_configs = group.cluster.nodes['all'].get_final_nodes().get_ordered_members_list(provide_node_configs=True)

    for node in group.get_ordered_members_list(provide_node_configs=True):
        package_associations = group.cluster.get_associations_for_node(node['connect_to'])['haproxy']
        configs_directory = '/'.join(package_associations['config_location'].split('/')[:-1])

        group.cluster.log.debug("\nConfiguring haproxy on \'%s\'..." % node['name'])
        config = get_config(group.cluster, node, all_nodes_configs)
        utils.dump_file(group.cluster, config, 'haproxy_%s.cfg' % node['name'])
        node['connection'].sudo('mkdir -p %s' % configs_directory)
        node['connection'].put(io.StringIO(config), package_associations['config_location'], backup=True, sudo=True)
        node['connection'].sudo('ls -la %s' % package_associations['config_location'])


def override_haproxy18(group):
    rhel_nodes = group.get_subgroup_with_os('rhel')
    if rhel_nodes.is_empty():
        group.cluster.log.debug('Haproxy18 override is not required')
        return
    package_associations = group.cluster.get_associations_for_os('rhel')['haproxy']
    # TODO: Do not replace the whole file, replace only parameter
    return group.put(io.StringIO("CONFIG=%s\n" % package_associations['config_location']),
                     '/etc/sysconfig/%s' % package_associations['service_name'], backup=True, sudo=True)
