import sys
import socket
import platform

from concurrent.futures import ThreadPoolExecutor, as_completed
from e1.ping import ping_host
from e1.cli_utils import get_ips_by_input
from util import get_local_ip


def find_network_hosts():
    if len(sys.argv) < 2 or not sys.argv[1].count('/'):
        print("Usage: python main.py <network>")
        print("Example: python main.py 192.168.1.0/24")
        sys.exit(1)
        return

    source_ip = get_local_ip()

    # network_ips = get_ips_by_input(sys.argv[1])
    network_ips = ['192.168.0.1']

    print("\n            Active hosts scan")
    print("=========================================")
    print(f"Scanning {len(network_ips)} IPs")
    print(f"First: {network_ips[0]} - Last: {network_ips[-1]}")
    print("=========================================\n...")

    icmp_results = {}

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_host, ip) for ip in network_ips]

        for future in as_completed(futures):
            ip, ping_response = future.result()
            if ping_response is not None and ip != source_ip:
                icmp_results[ip] = ping_response

    if not icmp_results:
        return []

    # Debug print
    # print("\nFound IPs with ICMP response:")
    # for ip, delay in icmp_results.items():
    #     print(f"IP: {ip} - Delay: {delay:.2f}ms")

    return list(icmp_results.keys())
