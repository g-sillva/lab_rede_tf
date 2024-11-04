import sys


def get_ips_by_input():
    ips = []

    if len(sys.argv) != 2:
        print("Usage: python3 main.py <network>")
        sys.exit(1)

    network, mask = sys.argv[1].split("/")

    # getting all the ips in the network based on the mask
    for i in range(2 ** (32 - int(mask))):
        if i == 0 or i == 255:
            continue

        ip = '.'.join(network.split(".")[:-1] + [str(i)])
        ips.append(ip)

    return ips

    