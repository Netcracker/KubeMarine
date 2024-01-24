from scapy.all import *
import sys

dst_ext = str(sys.argv[1])
dst_int = str(sys.argv[2])
port = int(sys.argv[3])
msg = str(sys.argv[4])

send(IP(dst=dst_ext)/IP(dst=dst_int)/UDP(dport=port)/msg)
