import sys
import socket

from e2.arp import get_mac_address, send_arp_reply

def run_arp_spoofing(target_ip):
    if target_ip == None:
        print("Error: Target IP is required, aborting...")
        sys.exit(1)
        return
    
    source_ip = socket.gethostbyname(socket.gethostname())
    source_mac = get_mac_address()

    target_mac = get_mac_address(ip=target_ip)
    
    print("\n        ARP Spoofing Attack")
    print("=========================================")
    print(f"Source host: {source_ip} ({source_mac})")
    print(f"Target host: {target_ip} ({target_mac})")
    print("=========================================\n...")

    print("\n FALTA FAZER O ENVIO DO ARP REPLY\n")
    # send_arp_reply(target_ip, target_mac, source_ip, source_mac)