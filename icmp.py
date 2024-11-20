import socket
import struct
import time
import select
from checksum import checksum
from ip import create_ip_header

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


def create_icmp_packet(identifier):
    """Cria um pacote ICMP"""
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, identifier, 1)
    data = b'Ping!' + (192 * b'Q')
    checksum_value = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0,
                         socket.htons(checksum_value), identifier, 1)
    return header + data


def send_ping(sock, src_addr, dest_addr, identifier):
    """Envia um pacote ICMP"""
    icmp_packet = create_icmp_packet(identifier)
    ip_header = create_ip_header(src_addr, dest_addr)
    packet = ip_header + icmp_packet
    sock.sendto(packet, (dest_addr, 0))


def receive_ping(sock, identifier, dest_addr, timeout=1):
    """Recebe pacotes ICMP"""
    time_left = timeout
    while True:
        start_time = time.time()
        ready = select.select([sock], [], [], time_left)
        time_spent = (time.time() - start_time)
        if not ready[0]:
            return None

        time_received = time.time()
        packet, addr = sock.recvfrom(1024)

        # Verificar o endereço de origem
        if addr[0] != dest_addr:
            continue

        # Extração do cabeçalho ICMP
        icmp_header = packet[20:28]
        icmp_type, _, _, packet_id, _ = struct.unpack("bbHHh", icmp_header)

        # Verificar o tipo ICMP e o identificador
        if icmp_type == ICMP_ECHO_REPLY and packet_id == identifier:
            return time_received

        time_left = time_left - time_spent
        if time_left <= 0:
            return None
