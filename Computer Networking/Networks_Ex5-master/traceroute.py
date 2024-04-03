import scapy
from scapy.all import sr1
from scapy.layers.inet import *
# https://stackoverflow.com/questions/69268731/module-scapy-has-no-attribute-ip-or-tcp-even-when-from-scapy-all-import
import sys

if len(sys.argv) != 2:
    print("python3 distance.py <IP>")
    exit()
else:
    ip = sys.argv[1]

response = None
ttl = 0

try:
    request = IP(dst=ip)/ICMP()  # Create ICMP packet
    response = sr1(request, timeout=3, verbose=0)  # Send ICMP packet and wait for response
    if response is None:
        print("Address could not be reached")
        exit()
    response = None
    while response is None or response.haslayer(ICMP) and response.getlayer(ICMP).type != 0:
        ttl += 1
        print("trying: ", ttl)
        request = IP(dst=ip, ttl=ttl)/ICMP()  # Create ICMP packet with TTL
        response = sr1(request, timeout=2, verbose=0)  # Send ICMP packet and wait for response

except KeyboardInterrupt:
    print("Exiting...")
    exit()
print("Distance to " + ip + ":", ttl)
