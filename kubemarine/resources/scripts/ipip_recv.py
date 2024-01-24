from scapy.all import *
import sys

ip = sys.argv[1]
dst = sys.argv[2]
msg = sys.argv[3]
port = int(sys.argv[4])
timeout = int(sys.argv[5])

fl = f"proto 4 and dst {dst}"

pkts = sniff(filter=fl, timeout=timeout)

for i in range(0, len(pkts)):
    src = pkts[i][IP].src
    if pkts[i][IP].payload.dst == ip and pkts[i][IP].payload.src == src:
        if pkts[i][IP].payload[UDP]:
            if pkts[i][IP].payload[UDP].dport == port:
                msg_rcv = bytes(pkts[i][IP].payload[UDP].payload).decode('utf8')
                if msg == msg_rcv:
                    print(src)
