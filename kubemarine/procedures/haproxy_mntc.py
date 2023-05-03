# Copyright 2021-2023 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from collections import OrderedDict
from kubemarine.core import flow
from kubemarine.core.action import Action
from kubemarine.core.resources import DynamicResources
 

def haproxy_mntc(cluster):

    nodes = []
    for node in cluster.procedure_inventory.get("nodes", cluster.nodes['all'].get_ordered_members_list(provide_node_configs=True)):
        if 'balancer' in node['roles']:
            nodes.append(node['name'])
            haproxy_mntc_node_group = cluster.make_group_from_nodes(nodes)

    os_family = haproxy_mntc_node_group.get_nodes_os()
    # Define the name of the service you want to update
    if os_family in ['rhel', 'rhel8']:
       service_name = "rh-haproxy18-haproxy"
    elif os_family == 'debian':
        service_name = "haproxy"
    # Define the path to the drop-in directory for the service
    drop_in_dir = f"/etc/systemd/system/{service_name}.service.d"
    select_conf_contents = "[Service]\nEnvironmentFile=/etc/systemd/system/haproxy.service.d/EnvFile\n"
    select_conf_name = "select.conf"
    select_conf_path = os.path.join(drop_in_dir, select_conf_name)
    env_file_name = "EnvFile"
    env_file_path = os.path.join(drop_in_dir, env_file_name)
    if not os.path.exists(drop_in_dir):
        haproxy_mntc_node_group.run("mkdir %s" % drop_in_dir , warn=True)
    
    mode = cluster.context.get('execution_arguments').get("mode")
    
    if mode == "enable":
      env_file_contents = "CONFIG=/etc/haproxy/haproxy_mntc.cfg\n"
    else:
      env_file_contents = "CONFIG=/etc/haproxy/haproxy.cfg\n"
   
    haproxy_mntc_node_group.sudo("""sh -c 'echo "%s" > %s' -v""" % (env_file_contents, env_file_path), warn=True)
    haproxy_mntc_node_group.sudo("""sh -c 'echo "%s" > %s' -v""" % (select_conf_contents, select_conf_path), warn=True)
    haproxy_mntc_node_group.sudo("systemctl daemon-reload", warn=True)
    haproxy_mntc_node_group.sudo("systemctl restart %s" % service_name, warn=True)


tasks = OrderedDict({
    "haproxy_mntc": haproxy_mntc,
    # "overview": install.overview,
})


class haproxy_mntcAction(Action):
    def __init__(self):
        super().__init__('haproxy_mntc')

    def run(self, res: DynamicResources):
        flow.run_tasks(res, tasks)


def main(cli_arguments=None):
    cli_help = '''
    Script for Enabling/Disabling Maintenance mode on HAProxy loadbalancer.

    How to use:

    kubemarine haproxy-mntc -m/--mode enbale/disable

    '''
    parser = flow.new_common_parser(cli_help)
    parser.add_argument('-m','--mode', dest='mode', default='', choices=["enable", "disable"], help='Mode of operation for HAProxy loadbalancer', required=True)

    context = flow.create_context(parser, cli_arguments, procedure='haproxy_mntc')

    flow.run_actions(context, [haproxy_mntcAction()])
    

if __name__ == '__main__':
    main()
