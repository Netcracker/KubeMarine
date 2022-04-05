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
