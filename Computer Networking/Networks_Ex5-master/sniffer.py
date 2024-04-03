import sys
import socket
import struct
import datetime


# Function to parse Ethernet header
def parse_ethernet_header(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    dest_mac = ':'.join('%02x' % b for b in eth_header[0])
    src_mac = ':'.join('%02x' % b for b in eth_header[1])
    eth_protocol = socket.ntohs(eth_header[2])
    return dest_mac, src_mac, eth_protocol, data[14:]


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


# Function to parse TCP header
def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    sequence_number = tcp_header[2]
    acknowledgement_number = tcp_header[3]
    data_offset_reserved = tcp_header[4]
    tcp_flags = tcp_header[5]
    window_size = tcp_header[6]
    tcp_checksum = tcp_header[7]
    return src_port, dest_port, sequence_number, acknowledgement_number, data_offset_reserved, tcp_flags, window_size, tcp_checksum, data[
                                                                                                                                     20:]


# Function to parse UDP header
def parse_udp_header(data):
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port = udp_header[0]
    dest_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]
    return src_port, dest_port, length, checksum, data[8:]


# Function to parse ICMP header
def parse_icmp_header(data):
    icmp_header = struct.unpack('!BBH', data[:4])
    type = icmp_header[0]
    code = icmp_header[1]
    checksum = icmp_header[2]
    return type, code, checksum, data[4:]


# Function to parse IGMP header
def parse_igmp_header(data):
    igmp_header = struct.unpack('!BBH4s', data[:8])
    type = igmp_header[0]
    max_response_time = igmp_header[1]
    checksum = igmp_header[2]
    group_address = socket.inet_ntoa(igmp_header[3])
    return type, max_response_time, checksum, group_address, data[8:]


# Main sniffing function
def sniff_packets():
    # Create a raw socket to capture packets
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Sniffing packets...")

    # Open the file to write packet information
    filename = "322653411_318471109.txt"
    with open(filename, "a") as file:
        while True:
            # Capture a packet and retrieve the raw data
            raw_data, addr = sniffer.recvfrom(65535)

            # Parse the Ethernet header
            dest_mac, src_mac, eth_protocol, packet_data = parse_ethernet_header(raw_data)

            # Filter TCP packets
            if eth_protocol == 8:  # IP packets
                version, ihl, ttl, protocol, src_ip, dest_ip, ip_data = parse_ip_header(packet_data)

                if protocol == 6:  # TCP packets
                    src_port, dest_port, sequence_number, acknowledgement_number, data_offset_reserved, tcp_flags, window_size, tcp_checksum, tcp_data = parse_tcp_header(
                        ip_data)
                    timestamp = str(datetime.datetime.now())
                    total_length = len(raw_data)
                    cache_flag = (tcp_flags >> 4) & 1
                    steps_flag = (tcp_flags >> 2) & 1
                    type_flag = tcp_flags & 3
                    status_code = tcp_checksum
                    cache_control = tcp_data[:6]
                    data = ":".join("{:02x}".format(b) for b in tcp_data[6:])

                    packet_info = {
                        "source_ip": src_ip, "dest_ip": dest_ip, "source_port": src_port, "dest_port": dest_port,
                        "timestamp": timestamp, "total_length": total_length, "cache_flag": cache_flag,
                        "steps_flag": steps_flag, "type_flag": type_flag, "status_code": status_code,
                        "cache_control": cache_control, "data": data
                    }

                    # Write packet info to the file
                    file.write(str(packet_info))
                    file.write("\n")

                elif protocol == 17:  # UDP packets
                    src_port, dest_port, length, checksum, udp_data = parse_udp_header(ip_data)
                    timestamp = str(datetime.datetime.now())
                    total_length = len(raw_data)
                    data = ":".join("{:02x}".format(b) for b in udp_data)

                    packet_info = {
                        "source_ip": src_ip,
                        "dest_ip": dest_ip,
                        "source_port": src_port,
                        "dest_port": dest_port,
                        "timestamp": timestamp,
                        "total_length": total_length,
                        "data": data
                    }

                    # Write packet info to the file
                    file.write(str(packet_info))
                    file.write("\n")

                elif protocol == 1:  # ICMP packets
                    type, code, checksum, icmp_data = parse_icmp_header(ip_data)
                    timestamp = str(datetime.datetime.now())
                    total_length = len(raw_data)
                    data = ":".join("{:02x}".format(b) for b in icmp_data)

                    packet_info = {
                        "source_ip": src_ip,
                        "dest_ip": dest_ip,
                        "type": type,
                        "code": code,
                        "timestamp": timestamp,
                        "total_length": total_length,
                        "data": data
                    }

                    # Write packet info to the file
                    file.write(str(packet_info))
                    file.write("\n")

                elif protocol == 2:  # IGMP packets
                    type, max_response_time, checksum, group_address, igmp_data = parse_igmp_header(ip_data)
                    timestamp = str(datetime.datetime.now())
                    total_length = len(raw_data)
                    data = ":".join("{:02x}".format(b) for b in igmp_data)

                    packet_info = {
                        "source_ip": src_ip,
                        "dest_ip": dest_ip,
                        "type": type,
                        "max_response_time": max_response_time,
                        "timestamp": timestamp,
                        "total_length": total_length,
                        "data": data
                    }

                    # Write packet info to the file
                    file.write(str(packet_info))
                    file.write("\n")

                else:
                    # Handle other protocols (RAW) here
                    timestamp = str(datetime.datetime.now())
                    total_length = len(raw_data)

                    packet_info = {
                        "source_ip": src_ip, "dest_ip": dest_ip, "protocol": protocol, "timestamp": timestamp,
                        "total_length": total_length, "data": ":".join("{:02x}".format(b) for b in ip_data)
                    }

                    # Write packet info to the file
                    file.write(str(packet_info))
                    file.write("\n")


# Start sniffing packets
sniff_packets()
