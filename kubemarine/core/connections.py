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
import threading
import time
from contextlib import contextmanager
from typing import Dict, List, Any, Optional, cast, Callable, Tuple, Iterator, IO, Union

import fabric  # type: ignore[import-untyped]
import fabric.transfer  # type: ignore[import-untyped]
import invoke
import paramiko

from kubemarine.core import static

input_sleep = fabric.Remote.input_sleep


class CommandInterrupted(invoke.Failure):
    pass


class RemoteRunner(fabric.Remote):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.KM_connection: Connection = cast(Connection, self.context)
        self.KM_interrupted = False

    def wait(self) -> None:
        while True:
            # Never raise KeyboardInterrupt. Remote result should be eventually returned, or raised.
            # This only sends SIGINT character, does not raise exception, and makes sense only with `pty`.
            # See invoke.Runner._finish() and fabric.Remote.send_interrupt()
            if self.using_pty and self.KM_connection.KM_interrupt_queue.acquire(blocking=False):
                self.KM_interrupted = True
                raise KeyboardInterrupt()

            # This repeats the behaviour of `invoke.Runner.wait()`
            if self.process_is_finished or self.has_dead_threads:
                break
            time.sleep(input_sleep)

    def generate_result(self, **kwargs: Any) -> fabric.Result:
        result = super().generate_result(**kwargs)

        # invoke converts CRs only on Windows. Let's always convert them to have stable output in memory for parsing.
        if not invoke.terminals.WINDOWS:
            result.stdout = result.stdout.replace("\r\n", "\n").replace("\r", "\n")
            result.stderr = result.stderr.replace("\r\n", "\n").replace("\r", "\n")

        # Raise CommandInterrupted only if pty is used and real SIGINT character is sent.
        if self.KM_interrupted:
            raise CommandInterrupted(result)

        return result


class TransferCallback:
    def __init__(self, connection: 'Connection'):
        self.connection = connection
        self.channel_lock = threading.Lock()
        self.interrupted = False

    def __call__(self, size: int, file_size: int) -> None:
        if self.connection.KM_interrupt_queue.acquire(blocking=False):
            sftp = self.connection.sftp()
            # This opens new SFTP channel on next access to SFTP client using the same connection.
            self.connection._sftp = None

            # We use prefetch for `Connection.get()` that fetches data in background.
            # If just raise KeyboardInterrupt, paramiko will attempt to close the remote file,
            # that will be queued after the prefetch.
            # In contrast, force closing of the SFTP channel does not hang up.
            # This is considered OK, as the remote file is eventually released,
            # and the only expected flaw is the channel can no longer be used.
            with self.channel_lock:
                self.interrupted = True
                sftp.close()

            raise KeyboardInterrupt()


class SFTPClient(paramiko.SFTPClient):
    def __init__(self, sock: paramiko.Channel):
        super().__init__(sock)
        self.KM_callback: Optional[TransferCallback] = None
        self.host = ""

    def getfo(self, remotepath: Union[bytes, str], fl: IO[bytes],
              callback: Callable[[int, int], object] = None, prefetch: bool = True,
              max_concurrent_prefetch_requests: int = None) -> int:
        return super().getfo(remotepath, fl,
                             callback=self.KM_callback, prefetch=True,
                             max_concurrent_prefetch_requests=max_concurrent_prefetch_requests)

    def putfo(self, fl: IO[bytes], remotepath: Union[bytes, str],
              file_size: int = 0, callback: Callable[[int, int], object] = None,
              confirm: bool = True) -> paramiko.SFTPAttributes:
        return super().putfo(fl, remotepath,
                             file_size=file_size, callback=self.KM_callback, confirm=confirm)

    def open(self, filename: Union[bytes, str], mode: str = "r", bufsize: int = -1) -> paramiko.SFTPFile:
        sftp_file = super().open(filename, mode, bufsize)

        # Paramiko starts daemon thread that prefetches the file.
        # If channel is closed from TransferCallback, the thread fails with an exception.
        # This monkey-patching is only needed to stop it gracefully.
        def _prefetch_thread(file: paramiko.SFTPFile, chunks: List[Tuple[int, int]],
                             max_concurrent_requests: int = None) -> None:
            for offset, length in chunks:
                callback = self.KM_callback
                if callback is None:
                    return
                with callback.channel_lock:
                    if callback.interrupted:
                        return

                    paramiko.SFTPFile._prefetch_thread(  # type: ignore[attr-defined] # pylint: disable=protected-access
                        file, [(offset, length)], max_concurrent_requests)

        # pylint: disable-next=protected-access,assignment-from-none,no-value-for-parameter
        sftp_file._prefetch_thread = _prefetch_thread.__get__(sftp_file, paramiko.SFTPFile)  # type: ignore[attr-defined]
        return sftp_file

    def close(self) -> None:
        try:
            super().close()
        except EOFError as e:
            self.logger.warning("Caught EOFError during closing sftp connection on host %s %s", self.host, e)

class Connection(fabric.Connection):  # type: ignore[misc]
    def __init__(self, host: str, **kwargs: Any):
        super().__init__(host, **kwargs)
        self._sftp: Optional[SFTPClient] = None
        self.KM_interrupt_queue = threading.Semaphore(0)

    def __setattr__(self, key: str, value: Any) -> None:
        # fabric Connection has special handling of this method. Call default behaviour for custom attributes.
        if key in ('_sftp', 'KM_interrupt_queue'):
            return object.__setattr__(self, key, value)
        super().__setattr__(key, value)

    @fabric.connection.opens  # type: ignore[misc]
    def sftp(self) -> SFTPClient:
        if self._sftp is None:
            self._sftp = cast(SFTPClient, SFTPClient.from_transport(self.client.get_transport()))
            self._sftp.host = self.host
        return self._sftp

    def get(self, *args: Any, **kwargs: Any) -> fabric.transfer.Result:
        with self.KM_transfer():
            return super().get(*args, **kwargs)

    def put(self, *args: Any, **kwargs: Any) -> fabric.transfer.Result:
        with self.KM_transfer():
            return super().put(*args, **kwargs)

    @contextmanager
    def KM_transfer(self) -> Iterator[None]:
        sftp = self.sftp()
        try:
            sftp.KM_callback = TransferCallback(self)
            yield
        finally:
            sftp.KM_callback = None

    def KM_start(self) -> None:
        self.KM_interrupt_queue = threading.Semaphore(0)

    def KM_interrupt(self) -> None:
        self.KM_interrupt_queue.release()


class ConnectionPool:
    def __init__(self, nodes: Dict[str, dict], gateway_nodes: Dict[str, dict], hosts: List[str]):
        self._nodes = nodes
        self._gateway_nodes = gateway_nodes
        self._connections = {ip: self._create_connection(ip) for ip in hosts}

    def get_node(self, ip: str) -> dict:
        node = self._nodes.get(ip)
        if node is None:
            raise Exception("Failed to find suitable node to connect to by address %s" % ip)

        return node

    def get_connection(self, ip: str) -> Connection:
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
                                        inline_ssh_env: bool = True) -> Connection:

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

        cfg = fabric.Config(overrides={
            'run': {'encoding': "utf-8"},
            'runners': {'remote': RemoteRunner},
        })
        return Connection(
            ip,
            user=conn_details.get('username', connection_defaults['username']),
            gateway=gateway,
            port=conn_details.get('connection_port', connection_defaults['port']),
            config=cfg,
            connect_timeout=connect_timeout,
            connect_kwargs=connect_kwargs,
            inline_ssh_env=inline_ssh_env
        )

    def _create_connection(self, ip: str) -> Connection:
        node = self.get_node(ip)

        if node.get('keyfile') is None and node.get('password') is None:
            raise Exception('There is neither keyfile nor password specified in configfile for node \'%s\'' % node['name'])

        gateway = None
        if 'gateway' in node:
            gateway = self._get_gateway_node_connection(node['gateway'])

        return self._create_connection_from_details(ip, node, gateway=gateway)

    def _get_gateway_node_connection(self, name: str) -> Connection:
        # Create new connection instance each time even if it is the same gateway node.
        # This is necessary to not share the same gateway connection instance in multiple threads

        gateway = self._gateway_nodes.get(name)
        if gateway is None:
            raise Exception('Requested gateway \'%s\' is not found in configfile' % name)

        return self._create_connection_from_details(gateway["address"], gateway, inline_ssh_env=False)
