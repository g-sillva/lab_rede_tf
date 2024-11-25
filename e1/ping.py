import socket
import os
import platform
import struct
import time
from util import get_local_ip
from e1.icmp import send_ping

def get_host_ip():
    """
    Retorna o endereço IP do host associado à interface de rede ativa.
    """
    try:
        # Usa um socket UDP para conectar a um IP não roteável (para evitar o envio de pacotes reais)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Servidor DNS público do Google
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        print(f"[!] Falha ao obter o IP do host: {e}")
        return None

def ping(dest_addr):
    """Função principal para enviar e receber pacotes ICMP."""
    try:
        if platform.system().lower() == 'linux':
            # Cria um socket RAW no Linux e associa à interface 'eth0'
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            sock.bind(('eth0', 0))

        elif platform.system().lower() == 'windows':
            # Cria um socket RAW no Windows e habilita o cabeçalho IP incluído
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        else:
            raise OSError("Plataforma não suportada")

    except PermissionError:
        print("Permissão negada. Execute o script com privilégios elevados (sudo).")
        return False

    src_addr = get_local_ip()  # Obtém o endereço IP local
    identifier = os.getpid() & 0xFFFF  # Usa o PID como identificador

    send_ping(sock, src_addr, dest_addr, identifier)  # Envia o pacote ICMP
    start_time = time.time()  # Marca o tempo de início
    sock.settimeout(1)  # Define o tempo de espera do socket para 1 segundo

    try:
        while True:
            response = sock.recv(1024)  # Recebe a resposta do socket
            eth_type = struct.unpack("!H", response[12:14])[0]  # Verifica o tipo Ether
            if eth_type != 0x0800:  # Verifica se é um pacote IP (0x0800)
                continue

            ip_header = response[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])  # Extrai o IP de origem
            dst_ip = socket.inet_ntoa(ip_header[16:20])  # Extrai o IP de destino

            if src_ip != dest_addr or dst_ip != src_addr:  # Verifica se os IPs são os esperados
                continue

            icmp_header = response[34:42]
            icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])  # Extrai o tipo e código ICMP
            if icmp_type == 0 and icmp_code == 0:  # Verifica se é uma resposta ICMP (Echo Reply)
                end_time = time.time()  # Marca o tempo de término
                elapsed_time = (end_time - start_time) * 1000  # Calcula o tempo de resposta em ms
                sock.close()
                return elapsed_time
    except socket.timeout:
        sock.close()
        return -1  # Retorna -1 em caso de timeout
    except Exception as e:
        sock.close()
        return -1  # Retorna -1 em caso de erro

def ping_host(ip):
    """Função wrapper para pingar um host"""
    return ip, ping(ip)