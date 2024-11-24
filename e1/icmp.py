import struct
import platform

from checksum import checksum
from e1.ip import create_ip_header
from e1.ethernet import create_ethernet_header

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


def create_icmp_packet(identifier):
    """Create an ICMP packet"""
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST,
                         ICMP_ECHO_REPLY, 0, identifier, 1)
    data = b'Ping!'
    checksum_value = checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY,
                         checksum_value, identifier, 1)
    return header + data


def send_ping(sock, src_addr, dest_addr, identifier):
    """Send an ICMP packet"""
    icmp_packet = create_icmp_packet(identifier)
    if platform.system().lower() == 'linux':
        ip_ethernet = create_ethernet_header('eth0')
        ip_header = create_ip_header(src_addr, dest_addr)
        packet = ip_ethernet + ip_header + icmp_packet
        sock.send(packet)
        return

    if platform.system().lower() == 'windows' or platform.system().lower() == 'linux':
        ip_header = create_ip_header(src_addr, dest_addr)
        packet = ip_header + icmp_packet
        sock.sendto(packet, (dest_addr, 0))
        return

    packet = icmp_packet
    sock.sendto(packet, (dest_addr, 0))
