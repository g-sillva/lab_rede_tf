import struct
import socket
import fcntl

def get_mac_address(interface):
    SIOCGIFHWADDR = 0x8927  # IOCTL to get hardware address
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        mac_address = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, struct.pack('256s', interface[:15].encode('utf-8')))
        return mac_address[18:24]
    finally:
        sock.close()


def create_ethernet_header(interface):
    src_mac = get_mac_address(interface)
    # Pack the header: destination MAC, source MAC, EtherType
    ethernet_header = struct.pack('!6s6sH', b'\xff\xff\xff\xff\xff\xff', src_mac, 0x0800)
    return ethernet_header
