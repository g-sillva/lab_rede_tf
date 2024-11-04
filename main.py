from cli_utils import get_ips_by_input

def main():
    # Getting all the ips in the network based
    network_ips = get_ips_by_input()

    print(network_ips)

    pass


if __name__ == '__main__':
    main()