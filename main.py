from cli_utils import get_ips_by_input

def main():
    # Getting all the ips in the network based
    network_ips = get_ips_by_input()

    # Store icmp results
    icmp_results = {}

    for ip in network_ips:
        print(f"Scanning {ip}")
        # create icmp packet
        # send icmp packet
        # store result
        pass
    

if __name__ == '__main__':
    main()