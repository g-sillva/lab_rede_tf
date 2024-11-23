import subprocess
import re
import struct
import socket
import platform

def send_arp_reply(target_ip, target_mac, source_ip, source_mac):
    """Send an ARP reply"""

    iface = "eth0"

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((iface, 0))

    arp_reply = create_arp_reply_header(target_ip, target_mac, source_ip, source_mac)
    sock.send(arp_reply)

    print(f"ARP reply sent to {target_ip} ({target_mac})")


def create_arp_reply_header(target_ip, target_mac, source_ip, source_mac):
    """Create an ARP reply header"""
    hardware_type = 1
    protocol_type = 0x0800
    hardware_address_length = 6
    protocol_address_length = 4
    operation = 2

    arp_reply = struct.pack("!HHBBH6s4s6s4s", hardware_type, protocol_type, 
                            hardware_address_length, protocol_address_length, operation,
                            bytes.fromhex(source_mac.replace(":", "")), socket.inet_aton(source_ip),
                            bytes.fromhex(target_mac.replace(":", "")), socket.inet_aton(target_ip))
    
    return arp_reply


def get_mac_address(ip=None):
    mac_pattern = r"([0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{1,2})"

    if not ip:
        # Local mac address
        if platform.system().lower() == "windows":
            try:
                output = subprocess.check_output(["ipconfig", "/all"], encoding="utf-8", errors="ignore")
                sections = output.split("\n\n")
                for section in sections:
                    if ('Sem fio' in section or 'Wi-Fi' in section) and '*' not in section:
                        match = re.search(mac_pattern, section)
                        if match:
                            return match.group(0).replace('-', ':').upper()
            except Exception as e:
                print(f"Error getting MAC address on Windows: {e}")
        else:
            try:
                output = subprocess.check_output(["ifconfig"], encoding="utf-8", errors="ignore")
                lines = output.splitlines()
            
                in_en0 = False
                for line in lines:
                    line = line.strip().replace("ether ", "")
                    if line.startswith("en0:"):
                        in_en0 = True
                    elif in_en0:
                        match = re.search(mac_pattern, line, re.IGNORECASE)
                        if match:
                            return match.group(1).upper()
                        if ":" in line and not line.startswith(" "):
                            in_en0 = False
            except Exception as e:
                print(f"Error getting MAC address on Linux: {e}")

    else:
        # Remote ip mac address
        output = subprocess.check_output(["arp", "-a"], encoding="utf-8", errors="ignore")
        lines = output.splitlines()

        if platform.system().lower() == "windows":
            try:
                for line in lines:
                    if ip in line:
                        match = re.search(mac_pattern, line)
                        if match:
                            return match.group(1).replace('-', ':').upper()
            except Exception as e:
                print(f"Error getting MAC address for {ip} on Windows: {e}")
        else:
            try:
                ip_pattern = rf"\? \({ip}\)"
                for line in lines:
                    if re.search(ip_pattern, line):
                        match = re.search(mac_pattern, line)
                        if match:
                            return match.group(1).upper()
            except Exception as e:
                print(f"Error getting MAC address for {ip} on Linux: {e}")