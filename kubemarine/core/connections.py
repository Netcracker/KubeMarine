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
import os
from typing import Dict, List

import fabric  # type: ignore[import-untyped]

from kubemarine.core import static

Connections = Dict[str, fabric.connection.Connection]


class ConnectionPool:
    def __init__(self, nodes: Dict[str, dict], gateway_nodes: Dict[str, dict], hosts: List[str]):
        self._nodes = nodes
        self._gateway_nodes = gateway_nodes
        self._connections: Connections = {ip: self._create_connection(ip) for ip in hosts}

    def get_node(self, ip: str) -> dict:
        node = self._nodes.get(ip)
        if node is None:
            raise Exception("Failed to find suitable node to connect to by address %s" % ip)

        return node

    def get_connection(self, ip: str) -> fabric.connection.Connection:
        conn = self._connections.get(ip)
        if conn is None:
            raise Exception(f'Connection for {ip} is not registered')

        return conn

    def close(self) -> None:
        for conn in self._connections.values():
            conn.close()

        self._connections.clear()

    def _create_connection_from_details(self, ip: str, conn_details: dict,
                                        gateway: fabric.connection.Connection = None,
                                        inline_ssh_env: bool = True) -> fabric.connection.Connection:

        connection_defaults = static.GLOBALS['connection']['defaults']
        connect_kwargs = {}
        if conn_details.get('keyfile'):
            connect_kwargs['key_filename'] = os.path.expanduser(conn_details['keyfile'])
        elif conn_details.get('password'):
            connect_kwargs['password'] = conn_details.get('password')

        # connect_timeout is for TCP connect, while channel_timeout is for SSH machinery.
        # Although they have different nature, there is no request to separate them for now.
        # channel_timeout can also be "worked around" by reconnecting the whole connection (including TCP connect)
        connect_timeout = conn_details.get('connection_timeout', connection_defaults['timeout'])
        connect_kwargs['channel_timeout'] = connect_timeout

        cfg = fabric.Config(overrides={'run': {'encoding': "utf-8"}})
        return fabric.connection.Connection(
            host=ip,
            user=conn_details.get('username', connection_defaults['username']),
            gateway=gateway,
            port=conn_details.get('connection_port', connection_defaults['port']),
            config=cfg,
            connect_timeout=connect_timeout,
            connect_kwargs=connect_kwargs,
            inline_ssh_env=inline_ssh_env
        )

    def _create_connection(self, ip: str) -> fabric.connection.Connection:
        node = self.get_node(ip)

        if node.get('keyfile') is None and node.get('password') is None:
            raise Exception('There is neither keyfile nor password specified in configfile for node \'%s\'' % node['name'])

        gateway = None
        if 'gateway' in node:
            gateway = self._get_gateway_node_connection(node['gateway'])

        return self._create_connection_from_details(ip, node, gateway=gateway)

    def _get_gateway_node_connection(self, name: str) -> fabric.connection.Connection:
        # Create new connection instance each time even if it is the same gateway node.
        # This is necessary to not share the same gateway connection instance in multiple threads

        gateway = self._gateway_nodes.get(name)
        if gateway is None:
            raise Exception('Requested gateway \'%s\' is not found in configfile' % name)

        return self._create_connection_from_details(gateway["address"], gateway, inline_ssh_env=False)
