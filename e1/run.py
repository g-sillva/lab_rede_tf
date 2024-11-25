import sys

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

    network_ips = get_ips_by_input(sys.argv[1])

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
            if ping_response != -1 and ip != source_ip:
                icmp_results[ip] = ping_response

    if not icmp_results:
        return []

    print("\nFound IPs with ICMP response:")
    for ip, delay in icmp_results.items():
        print(f"IP: {ip} - Delay: {delay:.2f}ms")

    return list(icmp_results.keys())


def select_target_host():
    hosts = find_network_hosts()
        
    if len(hosts) == 0:
        print("Error: No active hosts found in the network")
        return

    print(f"\nFound {len(hosts)} active host(s) in the network")

    print("\nSelect the target host to perform the attack:")
    for host, i in zip(hosts, range(1, len(hosts)+1)):
        print(f"({i}): {host}")
    print(f"({len(hosts)+1}): Exit")

    target_host = input("\nEnter the number of the target host: ")

    if not target_host.isdigit() or int(target_host) < 1 or int(target_host) > len(hosts)+1:
        print("Error: Invalid input")
        return select_target_host(hosts)

    if int(target_host) == len(hosts)+1:
        print("Exiting...")
        sys.exit(0)
        return None

    target_host = hosts[int(target_host)-1]

    confirmation = input(f"Do you confirm the target {target_host}? (Y/n): ")

    if confirmation.lower() == 'n' or confirmation.lower() == 'no':
        return select_target_host(hosts)
    elif confirmation and (confirmation.lower() != 'y' and confirmation.lower() != 'yes'):
        print("Error: Invalid input")
        return select_target_host(hosts)
    
    print(f"\nTarget host: {target_host}")
    return target_host