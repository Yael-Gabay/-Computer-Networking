from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP

# Define a callback function that analyzes packets
def packet_analysis(packet):
    # Check if the packet contains IP and TCP layers
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src  # Get the source IP address
        destination_ip = packet[IP].dst  # Get the destination IP address
        tcp_payload = str(packet[TCP].payload)  # Get the TCP payload (data)

        # Look for specific patterns indicating a login attempt
        #if 'username' in tcp_payload.lower() or 'password' in tcp_payload.lower():
        print(f"Packet Analysis: Source IP - {source_ip}, Destination IP - {destination_ip}")
        if packet.haslayer('Raw'):
        	try:
        		print(packet.getlayer('Raw').load.decode('utf-8'))
        	except UnicodeDecodeError:
        		print('n.a')
        #packet.show()


# Start capturing network packets
network_interface = "vethf542e00"  # Specify the interface to capture packets
filter_rule = "tcp port 23"  # Filter packets to only capture Telnet traffic

sniff(iface=network_interface, filter=filter_rule, prn=packet_analysis)
