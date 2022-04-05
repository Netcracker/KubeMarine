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

# Simple TCP socket listener in python 2, which accepts connection sequentially, and writes received data to stdout
# The script is for testing purpose only.
# The only argv parameter is a TCP port to listen.

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(('', int(sys.argv[1])))
s.listen(1)

while True:
    client, _ = s.accept()
    while True:
        data = client.recv(1024)
        if not data:
            break
        sys.stdout.write(data)

    client.close()
