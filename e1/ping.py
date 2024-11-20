import socket
import os
import time

from e1.icmp import send_ping, receive_ping

def ping(dest_addr):
    """Main function to send and receive ICMP packets"""
    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    except PermissionError:
        print("Permission denied. Try running as root.")
        return None

    src_addr = socket.gethostbyname(socket.gethostname())
    identifier = os.getpid() & 0xFFFF
    send_ping(sock, src_addr, dest_addr, identifier)

    start_time = time.time()
    response = receive_ping(sock, identifier, dest_addr)
    sock.close()

    if response:
        delay = (response - start_time) * 1000
        return delay
    return None

def ping_host(ip):
    """Wrapper function to ping a host"""
    return ip, ping(ip)