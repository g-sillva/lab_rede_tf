import socket
import struct
from checksum import checksum

def create_ip_header(src_addr, dest_addr):
    """Cria um cabeçalho IP"""
    ip_ihl = 5  # Tamanho do cabeçalho IP (5 palavras de 32 bits)
    ip_ver = 4  # Versão do IP (IPv4)
    ip_tos = 0  # Tipo de serviço (ToS) - padrão
    ip_tot_len = 20 + 8 + len(b"Ping!")  # Comprimento total do datagrama IP (cabeçalho IP + ICMP)
    ip_id = 54321  # Identificação do datagrama
    ip_frag_off = 0  # Offset do fragmento (sem fragmentação)
    ip_ttl = 64  # Tempo de vida (TTL)
    ip_proto = socket.IPPROTO_ICMP  # Protocolo (ICMP)
    ip_check = 0  # Checksum inicial (calculado depois)
    ip_saddr = socket.inet_aton(src_addr)  # Endereço de origem (convertido para formato de rede)
    ip_daddr = socket.inet_aton(dest_addr)  # Endereço de destino (convertido para formato de rede)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl  # Combina versão e IHL no mesmo byte

    # Empacota os campos do cabeçalho IP (com checksum inicial 0)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_saddr, ip_daddr)
    
    ip_check = checksum(ip_header)  # Calcula o checksum do cabeçalho IP
    
    # Reempacota o cabeçalho IP com o checksum calculado
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header  # Retorna o cabeçalho IP pronto