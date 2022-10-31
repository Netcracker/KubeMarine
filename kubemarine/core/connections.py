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

from typing import Dict

import fabric, os

from kubemarine.core.environment import Environment


Connections = Dict[str, fabric.connection.Connection]


class ConnectionPool:
    def __init__(self, env: Environment):
        self._env = env
        self._connections: Connections = {}

    def get_connection(self, ip: str) -> fabric.connection.Connection:
        conn = self._connections.get(ip)
        if conn is None:
            for node in self._env.inventory['nodes']:
                if node.get('address') == ip or node.get('internal_address') == ip or node.get('connect_to') == ip:
                    conn = self._create_connection(ip, node)

            if conn is None:
                raise Exception("Failed to find suitable node to connect to by address %s" % ip)

            self._connections[ip] = conn

        return conn

    def _create_connection_from_details(self, ip: str, conn_details: dict, gateway=None, inline_ssh_env=True):
        # fabric / invoke use default encoding of deployer.
        # We need to use encoding of remote nodes to correctly encode output of remote commands.
        # Currently remote nodes are always Linux, so hard-code 'utf-8'.
        cfg = fabric.Config(overrides={'run': {'encoding': "utf-8"}})
        return fabric.connection.Connection(
            host=ip,
            user=conn_details.get('username', self._env.globals['connection']['defaults']['username']),
            gateway=gateway,
            port=conn_details.get('connection_port', self._env.globals['connection']['defaults']['port']),
            config=cfg,
            connect_timeout=conn_details.get('connection_timeout',
                                             self._env.globals['connection']['defaults']['timeout']),
            connect_kwargs={
                "key_filename": os.path.expanduser(conn_details['keyfile'])
            },
            inline_ssh_env=inline_ssh_env
        )

    def _create_connection(self, ip: str, node: dict) -> fabric.connection.Connection:
        if node.get('keyfile') is None:
            raise Exception('There is no keyfile specified in configfile for node \'%s\'' % node['name'])

        gateway = None
        if 'gateway' in node:
            gateway = self._get_gateway_node_connection(node['gateway'])

        return self._create_connection_from_details(ip, node, gateway=gateway)

    def _get_gateway_node_connection(self, name: str) -> fabric.connection.Connection:
        # Create new connection instance each time even if it is the same gateway node.
        # This is necessary to not share the same gateway connection instance in multiple threads
        gateway_conn = None

        for gateway in self._env.inventory.get('gateway_nodes', []):
            if gateway.get('name') == name:
                if gateway.get('address') is None:
                    raise Exception('There is no address specified in configfile for gateway \'%s\'' % name)
                if gateway.get('keyfile') is None:
                    raise Exception('There is no keyfile specified in configfile for gateway \'%s\'' % name)

                # todo since we have no workaround for gateway connections currently,
                #  probably we need different default connection timeout
                gateway_conn = self._create_connection_from_details(
                    gateway["address"], gateway, inline_ssh_env=False)

        if gateway_conn is None:
            raise Exception('Requested gateway \'%s\' is not found in configfile' % name)

        return gateway_conn
