import socket
import struct
import sys

PACKET_LEN = 1500


def check_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False


def send_raw_ip_packet(ip, dest_ip, dest_port):
    # Step 1: Create a raw network socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Step 2: Provide needed information about destination.
    dest_info = (dest_ip, dest_port)

    # Step 3: Send the packet out.
    sock.sendto(ip, dest_info)
    sock.close()


class IPHeader:
    def __init__(self, saddr, daddr, protocol):
        self.version_ihl = (4 << 4) | 5  # IPv4 and header length
        self.tos = 0  # Type of Service
        self.tot_len = 0  # Total length (will be filled later)
        self.id = 54321  # Identification
        self.flags_fragoffset = 0  # Flags and Fragment Offset
        self.ttl = 20  # Time to Live
        self.protocol = protocol  # Protocol (ICMP, UDP, or TCP)
        self.check = 0  # Checksum (will be filled later)
        self.saddr = socket.inet_aton(saddr)  # Source IP address
        self.daddr = socket.inet_aton(daddr)  # Destination IP address

    def pack(self):
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                self.version_ihl,
                                self.tos,
                                self.tot_len,
                                self.id,
                                self.flags_fragoffset,
                                self.ttl,
                                self.protocol,
                                self.check,
                                self.saddr,
                                self.daddr)

        return ip_header


class ICMPHeader:
    def __init__(self):
        self.type = 8  # ICMP Echo Request
        self.code = 0  # Code
        self.checksum = 0  # Checksum (will be filled later)
        self.identifier = 0  # Identifier
        self.seq = 0  # Sequence Number

    def pack(self):
        icmp_header = struct.pack('!BBHHH',
                                  self.type,
                                  self.code,
                                  self.checksum,
                                  self.identifier,
                                  self.seq)

        return icmp_header


class UDPHeader:
    def __init__(self, sport, dport):
        self.sport = sport  # Source port
        self.dport = dport  # Destination port
        self.length = 8  # Length (UDP header size)
        self.checksum = 0  # Checksum (will be filled later)

    def pack(self, ip_header):
        pseudo_header = struct.pack('!4s4sBBH',
                                    ip_header.saddr,
                                    ip_header.daddr,
                                    0,
                                    ip_header.protocol,
                                    self.length)

        udp_header = struct.pack('!HHHH',
                                 self.sport,
                                 self.dport,
                                 self.length,
                                 self.checksum)

        # Calculate UDP checksum
        checksum_buf = pseudo_header + udp_header

        udp_header = struct.pack('!HHHH',
                                 self.sport,
                                 self.dport,
                                 self.length,
                                 self.checksum)

        return udp_header


class TCPHeader:
    def __init__(self, sport, dport, seq, ack_seq):
        self.sport = sport  # Source port
        self.dport = dport  # Destination port
        self.seq = seq  # Sequence Number
        self.ack_seq = ack_seq  # Acknowledgment Number
        self.doff = 5  # Data Offset
        self.flags = 0x02  # Flags (SYN)
        self.window = socket.htons(5840)  # Window Size
        self.checksum = 0  # Checksum (will be filled later)
        self.urg_ptr = 0  # Urgent Pointer

    def pack(self, ip_header):
        pseudo_header = struct.pack('!4s4sBBH',
                                    ip_header.saddr,
                                    ip_header.daddr,
                                    0,
                                    ip_header.protocol,
                                    20)  # TCP header size

        tcp_header = struct.pack('!HHLLBBHHH',
                                 self.sport,
                                 self.dport,
                                 self.seq,
                                 self.ack_seq,
                                 (self.doff << 4),
                                 self.flags,
                                 self.window,
                                 self.checksum,
                                 self.urg_ptr)

        # Calculate TCP checksum
        checksum_buf = pseudo_header + tcp_header

        tcp_header = struct.pack('!HHLLBBHHH', self.sport, self.dport, self.seq, self.ack_seq, (self.doff << 4),
                                 self.flags, self.window,
                                 self.checksum,
                                 self.urg_ptr)

        return tcp_header


def main():
    # Receive IP from user
    ip = "1.1.1.1"
    if len(sys.argv) > 1:
        ip = sys.argv[1]

    # Verify validity of IP
    if not check_ip(ip):
        print("Sorry, but this is not a valid IP address. Please try again.")
        return

    dest_ip = input("Enter the destination IP address: ")

    # Verify validity of destination IP
    if not check_ip(dest_ip):
        print("Sorry, but this is not a valid destination IP address. Please try again.")
        return

    buffer = bytearray(PACKET_LEN)
    buffer[:PACKET_LEN] = b'\x00' * PACKET_LEN

    # Create ICMP packet
    icmp = ICMPHeader()
    icmp_packet = icmp.pack()

    # Create IP header for ICMP packet
    ip_header_icmp = IPHeader(ip, "1.2.3.4", socket.IPPROTO_ICMP)
    ip_header_icmp.tot_len = socket.htons(len(ip_header_icmp.pack()) + len(icmp_packet))

    print("Sending spoofed IP packet...\n")
    print("~~~~~ ICMP Packet ~~~~~\n")
    print("IP Header")
    print("IP Total Length: {} Bytes".format(socket.ntohs(ip_header_icmp.tot_len)))
    print("src IP: {}".format(socket.inet_ntoa(ip_header_icmp.saddr)))
    print("dst IP: {}".format(socket.inet_ntoa(ip_header_icmp.daddr)))
    print("\nICMP Header")
    print("Type: {}".format(icmp.type))
    print("Seq: {}".format(icmp.seq))

    send_raw_ip_packet(ip_header_icmp.pack() + icmp_packet, dest_ip, 0)  # Use 0 as the destination port for ICMP
    print("ICMP packet sent successfully.")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    # Create UDP packet
    udp = UDPHeader(12345, 54321)
    udp_packet = udp.pack(ip_header_icmp)

    # Create IP header for UDP packet
    ip_header_udp = IPHeader(ip, "1.2.3.4", socket.IPPROTO_UDP)
    ip_header_udp.tot_len = socket.htons(len(ip_header_udp.pack()) + len(udp_packet))

    print("\n\nSending spoofed IP packet...\n")
    print("~~~~~ UDP Packet ~~~~~\n")
    print("IP Header")
    print("IP Total Length: {} Bytes".format(socket.ntohs(ip_header_udp.tot_len)))
    print("src IP: {}".format(socket.inet_ntoa(ip_header_udp.saddr)))
    print("dst IP: {}".format(socket.inet_ntoa(ip_header_udp.daddr)))
    print("\nUDP Header")
    print("src Port: {}".format(udp.sport))
    print("dst Port: {}".format(udp.dport))

    send_raw_ip_packet(ip_header_udp.pack() + udp_packet, dest_ip, udp.dport)
    print("UDP packet sent successfully.")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    # Create TCP packet
    tcp = TCPHeader(12345, 80, 1000, 0)
    tcp_packet = tcp.pack(ip_header_icmp)

    # Create IP header for TCP packet
    ip_header_tcp = IPHeader(ip, "1.2.3.4", socket.IPPROTO_TCP)
    ip_header_tcp.tot_len = socket.htons(len(ip_header_tcp.pack()) + len(tcp_packet))

    print("\n\nSending spoofed IP packet...\n")
    print("~~~~~ TCP Packet ~~~~~\n")
    print("IP Header")
    print("IP Total Length: {} Bytes".format(socket.ntohs(ip_header_tcp.tot_len)))
    print("src IP: {}".format(socket.inet_ntoa(ip_header_tcp.saddr)))
    print("dst IP: {}".format(socket.inet_ntoa(ip_header_tcp.daddr)))
    print("\nTCP Header")
    print("src Port: {}".format(tcp.sport))
    print("dst Port: {}".format(tcp.dport))
    print("Seq: {}".format(tcp.seq))
    print("Ack: {}".format(tcp.ack_seq))

    send_raw_ip_packet(ip_header_tcp.pack() + tcp_packet, dest_ip, tcp.dport)
    print("TCP packet sent successfully.")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


if __name__ == "__main__":
    main()
