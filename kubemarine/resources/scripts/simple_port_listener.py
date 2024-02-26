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

# Simple TCP socket listener that can be run on both python 2 and 3,
# The listener accepts connections sequentially, and suppresses the received data.
# The script is for testing purpose only.
# The first argv parameter is the TCP port to listen. The second argv parameter is the ip protocol version.

import socket
import sys

port = int(sys.argv[1])

proto = '{{ proto }}'
ip_version = '{{ ip_version }}'

s_type = socket.SOCK_STREAM
if proto == 'udp':
    s_type = socket.SOCK_DGRAM

family = socket.AF_INET
if ip_version == '6':
    family = socket.AF_INET6

s = socket.socket(family, s_type)
try:
    try:
        s.bind(('{{ address }}', port))
    except socket.error as e:
        if "Address already in use" in str(e):
            sys.stdout.write("In use\n")
            sys.stdout.flush()
            exit(1)
        else:
            raise

    sys.stdout.write("Listen\n")
    sys.stdout.flush()

    sz = int('{{ mtu }}')

    if proto == 'udp':
        while True:
            data, address = s.recvfrom(sz)
            s.sendto(data, address)

    else:
        s.listen(1)

        while True:
            client, _ = s.accept()
            try:
                while True:
                    data = client.recv(sz)
                    if not data:
                        break
                    client.sendall(data)
            finally:
                client.close()
finally:
    s.close()
