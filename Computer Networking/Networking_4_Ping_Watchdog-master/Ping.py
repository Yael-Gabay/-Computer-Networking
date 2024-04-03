import scapy
from scapy.all import sr1
from scapy.layers.inet import *
# https://stackoverflow.com/questions/69268731/module-scapy-has-no-attribute-ip-or-tcp-even-when-from-scapy-all-import
import sys
import time

if len(sys.argv) != 2:
    print("python3 Ping.py <IP>")
    exit()
else:
    ip = sys.argv[1]

try:
    while True:
        start = time.time()
        request = IP(dst=ip)/ICMP()  # Create ICMP packet

        response = sr1(request, timeout=1, verbose=0)  # Send ICMP packet and wait for response
        end = time.time()
        print('Reply from ' + ip + ': bytes='+ str(len(response)) + ' time=' + str(round((end - start) * 1000)) + 'ms')

except KeyboardInterrupt:
    print("Exiting...")
    exit()
