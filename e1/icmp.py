import struct
import platform

from checksum import checksum
from e1.ip import create_ip_header
from e1.ethernet import create_ethernet_header

ICMP_ECHO_REQUEST = 8  # Tipo de mensagem ICMP para Echo Request (ping)
ICMP_ECHO_REPLY = 0  # Tipo de mensagem ICMP para Echo Reply (resposta ao ping)

def create_icmp_packet(identifier):
    """Cria um pacote ICMP"""
    # Monta o cabeçalho ICMP com tipo, código, checksum (inicialmente 0), identificador e número de sequência
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY, 0, identifier, 1)
    data = b'Ping!'  # Dados arbitrários para incluir no pacote ICMP
    checksum_value = checksum(header + data)  # Calcula o checksum sobre o cabeçalho e dados
    # Recria o cabeçalho ICMP agora com o checksum calculado
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY, checksum_value, identifier, 1)
    return header + data  # Retorna o pacote ICMP completo (cabeçalho + dados)

def send_ping(sock, src_addr, dest_addr, identifier):
    """Envia um pacote ICMP"""
    icmp_packet = create_icmp_packet(identifier)  # Cria o pacote ICMP
    system = platform.system().lower()  # Obtém o sistema operacional em minúsculas

    # Se for Linux, monta e envia um pacote Ethernet/IP/ICMP
    if system == 'linux':
        ip_ethernet = create_ethernet_header('eth0')  # Cria o cabeçalho Ethernet
        ip_header = create_ip_header(src_addr, dest_addr)  # Cria o cabeçalho IP
        packet = ip_ethernet + ip_header + icmp_packet  # Monta o pacote completo
        sock.send(packet)  # Envia o pacote pela rede
        return

    # Se for Windows ou Linux, monta e envia um pacote IP/ICMP
    if system == 'windows' or system == 'linux':
        ip_header = create_ip_header(src_addr, dest_addr)  # Cria o cabeçalho IP
        packet = ip_header + icmp_packet  # Monta o pacote IP/ICMP
        sock.sendto(packet, (dest_addr, 0))  # Envia o pacote para o endereço de destino e porta 0
        return

    # Em outros sistemas operacionais, envia apenas o pacote ICMP sem cabeçalho IP
    packet = icmp_packet
    sock.sendto(packet, (dest_addr, 0))  # Envia o pacote ICMP diretamente