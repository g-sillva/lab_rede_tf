import socket
import struct
import time
import select
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

    if platform.system().lower() == 'windows':
        ip_header = create_ip_header(src_addr, dest_addr)
        packet = ip_header + icmp_packet
        sock.sendto(packet, (dest_addr, 0))
        return

    packet = icmp_packet
    sock.sendto(packet, (dest_addr, 0))


def receive_ping(sock, identifier, dest_addr, timeout=1):
    """Receive an ICMP packet"""
    time_left = timeout
    while True:
        start_time = time.time()
        ready = select.select([sock], [], [], time_left)
        time_spent = (time.time() - start_time)
        if not ready[0]:
            return None

        time_received = time.time()
        response = sock.recv()

        print(response)
        return
        # # if addr[0] != dest_addr:
        # #     continue

        # # icmp_header = packet[20:28]
        # icmp_type, _, _, packet_id, _ = struct.unpack("bbHHh", icmp_header)

        # print(icmp_type, ICMP_ECHO_REPLY, packet_id, identifier)
        # if icmp_type == ICMP_ECHO_REPLY and packet_id == identifier:
        #     return time_received

        # print(time_left, time_spent)
        # time_left = time_left - time_spent
        # if time_left <= 0:
        #     return None
