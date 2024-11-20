import socket
import os
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from cli_utils import get_ips_by_input
from icmp import send_ping, receive_ping


def ping(dest_addr):
    """Função principal para enviar e receber pings"""
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("Permissão negada. Execute o script como administrador.")
        return None

    src_addr = socket.gethostbyname(socket.gethostname())
    identifier = os.getpid() & 0xFFFF
    send_ping(sock, src_addr, dest_addr, identifier)

    start_time = time.time()
    response = receive_ping(sock, identifier, dest_addr)
    sock.close()

    if response:
        delay = (response - start_time) * 1000
        return delay
    return None


def ping_host(ip):
    """Função wrapper para pingar um único IP"""
    print(f"Pinging {ip}")
    return ip, ping(ip)


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <network>")
        print("Example: python main.py 192.168.1.0/24")
        return

    # network_ips = ['192.168.240.26']
    network_ips = get_ips_by_input(sys.argv[1])

    print("=========================================")
    print(f"Scanning {len(network_ips)} IPs")
    print(f"First: {network_ips[0]} - Last: {network_ips[-1]}")
    print("=========================================")

    # Store ICMP results
    icmp_results = {}

    # Usar ThreadPoolExecutor para rodar pings em paralelo
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(ping_host, ip) for ip in network_ips]

        for future in as_completed(futures):
            ip, ping_response = future.result()
            if ping_response is not None:
                icmp_results[ip] = ping_response

    print("\nFound IPs with ICMP response:")
    for ip, delay in icmp_results.items():
        print(f"IP: {ip} - Delay: {delay:.2f}ms")


if __name__ == '__main__':
    main()
