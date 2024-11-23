import socket
import struct
from checksum import checksum

def create_ip_header(src_addr, dest_addr):
    """Create an IP header"""
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 8 + len(b"Ping!")  # IP Header + ICMP Header
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_addr)
    ip_daddr = socket.inet_aton(dest_addr)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_saddr, ip_daddr)
    
    ip_check = checksum(ip_header)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, socket.htons(ip_check), ip_saddr, ip_daddr)
    return ip_header
