import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from e1.ping import ping_host
from e1.cli_utils import get_ips_by_input
from util import get_local_ip

def find_network_hosts():
    """
    Esta função escaneia a rede fornecida para encontrar hosts ativos.
    """
    if len(sys.argv) < 2 or not sys.argv[1].count('/'):
        # Verifica se o argumento de rede foi fornecido corretamente
        print("Usage: python main.py <network>")
        print("Example: python main.py 192.168.1.0/24")
        sys.exit(1)

    source_ip = get_local_ip()  # Obtém o endereço IP local

    network_ips = get_ips_by_input(sys.argv[1])  # Obtém todos os IPs na rede fornecida

    print("\n            Active hosts scan")
    print("=========================================")
    print(f"Scanning {len(network_ips)} IPs")
    print(f"First: {network_ips[0]} - Last: {network_ips[-1]}")
    print("=========================================\n...")

    icmp_results = {}  # Dicionário para armazenar os resultados dos pings

    with ThreadPoolExecutor(max_workers=50) as executor:
        # Cria uma pool de threads para enviar pings de forma concorrente
        futures = [executor.submit(ping_host, ip) for ip in network_ips]

        for future in as_completed(futures):
            # Processa cada resultado assim que a execução da thread é concluída
            ip, ping_response = future.result()
            if ping_response != -1 and ip != source_ip:
                icmp_results[ip] = ping_response  # Armazena os IPs que responderam ao ping

    if not icmp_results:
        # Se nenhum host respondeu ao ping, retorna uma lista vazia
        return []

    print("\nFound IPs with ICMP response:")
    for ip, delay in icmp_results.items():
        # Exibe os IPs que responderam ao ping juntamente com o tempo de resposta
        print(f"IP: {ip} - Delay: {delay:.2f}ms")

    return list(icmp_results.keys())  # Retorna uma lista de IPs que responderam ao ping

def select_target_host():
    """
    Esta função auxilia o usuário na seleção de um host alvo dentre os hosts ativos na rede.
    """
    hosts = find_network_hosts()  # Encontra hosts ativos na rede
        
    if len(hosts) == 0:
        # Se nenhum host ativo for encontrado, exibe uma mensagem de erro
        print("Error: No active hosts found in the network")
        return

    print(f"\nFound {len(hosts)} active host(s) in the network")

    print("\nSelect the target host to perform the attack:")
    for host, i in zip(hosts, range(1, len(hosts)+1)):
        # Lista todos os hosts ativos para que o usuário possa selecionar o alvo
        print(f"({i}): {host}")
    print(f"({len(hosts)+1}): Exit")

    target_host = input("\nEnter the number of the target host: ")

    if not target_host.isdigit() or int(target_host) < 1 or int(target_host) > len(hosts)+1:
        # Verifica se a entrada do usuário é válida
        print("Error: Invalid input")
        return select_target_host(hosts)

    if int(target_host) == len(hosts)+1:
        # Se o usuário escolheu sair, encerra o programa
        print("Exiting...")
        sys.exit(0)

    target_host = hosts[int(target_host)-1]  # Obtém o host alvo baseado na escolha do usuário

    confirmation = input(f"Do you confirm the target {target_host}? (Y/n): ")

    if confirmation.lower() == 'n' or confirmation.lower() == 'no':
        # Se o usuário não confirma, reinicia a seleção do host alvo
        return select_target_host(hosts)
    elif confirmation and (confirmation.lower() != 'y' and confirmation.lower() != 'yes'):
        # Verifica se a entrada de confirmação do usuário é válida
        print("Error: Invalid input")
        return select_target_host(hosts)
    
    print(f"\nTarget host: {target_host}")
    return target_host  # Retorna o host alvo confirmado