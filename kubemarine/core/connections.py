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
    def __init__(self, inventory: dict, hosts: List[str]):
        self.inventory = inventory
        self._connections: Connections = {ip: self._create_connection(ip) for ip in hosts}

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

        creds={}
        if conn_details.get('keyfile'):
            creds['key_filename'] = os.path.expanduser(conn_details['keyfile'])
        elif conn_details.get('password'):
            creds['password'] = conn_details.get('password')
        cfg = fabric.Config(overrides={'run': {'encoding': "utf-8"}})
        return fabric.connection.Connection(
            host=ip,
            user=conn_details.get('username', static.GLOBALS['connection']['defaults']['username']),
            gateway=gateway,
            port=conn_details.get('connection_port', static.GLOBALS['connection']['defaults']['port']),
            config=cfg,
            connect_timeout=conn_details.get('connection_timeout',
                                             static.GLOBALS['connection']['defaults']['timeout']),
            connect_kwargs=creds,
            inline_ssh_env=inline_ssh_env
        )

    def _create_connection(self, ip: str) -> fabric.connection.Connection:
        for node in self.inventory.get('nodes', []):
            if node.get('connect_to') == ip:
                break
        else:
            raise Exception("Failed to find suitable node to connect to by address %s" % ip)

        if node.get('keyfile') is None and node.get('password') is None:
            raise Exception('There is neither keyfile nor password specified in configfile for node \'%s\'' % node['name'])

        gateway = None
        if 'gateway' in node:
            gateway = self._get_gateway_node_connection(node['gateway'])

        return self._create_connection_from_details(ip, node, gateway=gateway)

    def _get_gateway_node_connection(self, name: str) -> fabric.connection.Connection:
        # Create new connection instance each time even if it is the same gateway node.
        # This is necessary to not share the same gateway connection instance in multiple threads
        gateway_conn = None

        for gateway in self.inventory.get('gateway_nodes', []):
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


EMPTY_POOL = ConnectionPool({}, [])
