def get_ips_by_input(network):
    ips = []

    # Divide o endereço de rede (IP) e a máscara (prefixo) a partir do formato CIDR (ex: 192.168.1.0/24)
    network_ip, mask = network.split("/")
        
    # Obtém todos os IPs na rede com base na máscara
    for i in range(2 ** (32 - int(mask))):
        # Pula o endereço de rede, o primeiro endereço utilizável e o endereço de broadcast
        if i == 0 or i == 1 or i == 255:
            continue

        # Gera o IP substituindo o último octeto com o valor de 'i'
        ip = '.'.join(network_ip.split(".")[:-1] + [str(i)])
        ips.append(ip)

    return ips