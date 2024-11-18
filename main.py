from cli_utils import get_ips_by_input

import socket
import struct
import os
import time
import select
import sys

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def checksum(source_string):
    """Calcula o checksum do cabeçalho"""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet(identifier):
    """Cria um pacote ICMP"""
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, identifier, 1)
    data = b'Ping!' + (192 * b'Q')
    checksum_value = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_value), identifier, 1)
    return header + data

def send_ping(sock, dest_addr, identifier):
    """Envia um pacote ICMP"""

    icmp_header = create_icmp_packet(identifier)

    packet = icmp_header
    sock.sendto(packet, (dest_addr, 0))

def receive_ping(sock, identifier, timeout=1):
    """Recebe pacotes ICMP"""
    time_left = timeout
    while True:
        start_time = time.time()
        ready = select.select([sock], [], [], time_left)
        time_spent = (time.time() - start_time)
        if not ready[0]:
            return None

        time_received = time.time()
        packet, _ = sock.recvfrom(1024)
        icmp_header = packet[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

        if type == ICMP_ECHO_REPLY and packet_id == identifier:
            return time_received

        time_left = time_left - time_spent
        if time_left <= 0:
            return None

def ping(dest_addr):
    """Função principal para enviar e receber pings"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Permissão negada")
        return

    identifier = os.getpid() & 0xFFFF
    send_ping(sock, dest_addr, identifier)
    # print(f"Enviando ping para {dest_addr}...")

    start_time = time.time()
    response = receive_ping(sock, identifier)
    if response:
        delay = (response - start_time) * 1000
        return delay
        # print(f"Resposta de {dest_addr} em {delay:.2f}ms")

    sock.close()
    return None

def main():

    if not len(sys.argv) > 1:
        print("Usage: python main.py <network>")
        print("Example: python main.py 127.0.0.0/28")
        return

    network_ips = get_ips_by_input(sys.argv[1])
    
    print("=========================================")
    print(f"Scanning {len(network_ips)} IPs")
    print(f"{network_ips[0]} - Last {network_ips[-1]}")
    print("=========================================")

    # Store icmp results
    icmp_results = {}

    for ip in network_ips:
        print(f"Scanning {ip}")
        
        ping_response = ping(ip)
        if ping_response:
            icmp_results[ip] = ping_response

    print("\nFound IPs with ICMP response:")
    for ip, delay in icmp_results.items():
        print(f"IP: {ip} - Delay: {delay:.2f}ms")

if __name__ == '__main__':
    main()
