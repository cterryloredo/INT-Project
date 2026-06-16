#!/usr/bin/env python3
# UDP traffic generator for INT, runs inside a Mininet host.
# Inside the p4app container this file is available at /tmp/utils/sender.py.
#
# Usage (from the Mininet CLI):  hN python3 /tmp/utils/sender.py <dst> <count> [src]
#   src defaults to 10.0.1.1 (h1).
#   INT-XD flow: h1 python3 /tmp/utils/sender.py 10.0.2.2 500 10.0.1.1   (10.0.1.1 -> 10.0.2.2)
#   INT-MD flow: h2 python3 /tmp/utils/sender.py 10.0.1.1 500 10.0.2.2   (10.0.2.2 -> 10.0.1.1)
# Only 10.0.1.1->10.0.2.2 matches the committed INT-XD watchlist; the MD flow needs the
# MD source entry in commands2.txt (see README_INT_XD.md).
import socket, time, sys
dst = sys.argv[1] if len(sys.argv) > 1 else '10.0.2.2'
n   = int(sys.argv[2]) if len(sys.argv) > 2 else 400
src = sys.argv[3] if len(sys.argv) > 3 else '10.0.1.1'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind((src, 4000))
except OSError:
    s.bind((src, 0))
for _ in range(n):
    s.sendto(b'inttest', (dst, 5000))
    time.sleep(0.008)          # ~125 pps, under the 500 pps ceiling
print('sender done ->', src, '->', dst, n)
