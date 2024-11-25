import struct
import socket
import fcntl

def get_mac_address(interface):
    SIOCGIFHWADDR = 0x8927  # IOCTL para obter endereço de hardware (MAC)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Cria um socket de rede
    try:
        # Usa ioctl para obter o endereço MAC da interface de rede especificada
        # 'struct.pack' empacota a interface dentro do formato necessário para a chamada ioctl
        mac_address = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, struct.pack('256s', interface[:15].encode('utf-8')))
        return mac_address[18:24]  # Retorna o endereço MAC da resposta (bytes 18 a 24)
    finally:
        sock.close()  # Garante que o socket será fechado, mesmo em caso de erro

def create_ethernet_header(interface):
    src_mac = get_mac_address(interface)  # Obtém o endereço MAC da interface fornecida
    # Monta o cabeçalho Ethernet: MAC de destino (broadcast), MAC de origem e EtherType (IPv4 no caso, 0x0800)
    ethernet_header = struct.pack('!6s6sH', b'\xff\xff\xff\xff\xff\xff', src_mac, 0x0800)
    return ethernet_header  # Retorna o cabeçalho Ethernet criado