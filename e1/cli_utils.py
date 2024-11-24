def get_ips_by_input(network):
    ips = []

    network_ip, mask = network.split("/")
        
    # getting all the ips in the network based on the mask
    for i in range(2 ** (32 - int(mask))):
        if i == 0 or i == 1 or i == 255:
            continue

        ip = '.'.join(network_ip.split(".")[:-1] + [str(i)])
        ips.append(ip)

    return ips

    