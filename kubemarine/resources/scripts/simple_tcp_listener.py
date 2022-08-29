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

if sys.argv[2] == '6' :
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
else:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind(('', int(sys.argv[1])))
except socket.error as e:
    if "Address already in use" in str(e):
        sys.stdout.write("In use\n")
        sys.stdout.flush()
        exit(1)
    else:
        raise

sys.stdout.write("Listen\n")
sys.stdout.flush()
s.listen(1)

while True:
    client, _ = s.accept()
    while True:
        data = client.recv(1024)
        if not data:
            break

    client.close()
