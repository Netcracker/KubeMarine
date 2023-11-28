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
import socket
import sys

action = sys.argv[1]
port = int(sys.argv[2])
address = sys.argv[3]
ip_version = sys.argv[4]

proto = '{{ proto }}'

s_type = socket.SOCK_STREAM
if proto == 'udp':
    s_type = socket.SOCK_DGRAM

family = socket.AF_INET
if ip_version == '6':
    family = socket.AF_INET6

s = socket.socket(family, s_type)
try:
    s.settimeout(int('{{ timeout }}'))

    sz = int('{{ mtu }}')

    if proto == 'udp':
        s.sendto(os.urandom(sz), (address, port))
        data, server = s.recvfrom(sz)
    else:
        s.connect((address, port))
        data = bytearray()
        if action == 'send':
            s.sendall(os.urandom(sz))
            while len(data) < sz:
                data.extend(s.recv(sz))
finally:
    s.close()

if action == 'send' and len(data) != sz:
    sys.stdout.write("Data is lost\n")
    sys.stdout.flush()
    exit(1)
