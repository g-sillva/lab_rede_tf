import socket
import os
import time
import platform

from e1.icmp import send_ping, receive_ping


def get_host_ip():
    """
    Returns the host's IP address associated with the active network interface.
    """
    try:
        # Use a UDP socket to connect to a non-routable IP (to avoid sending actual packets)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Google Public DNS server
            ip_address = s.getsockname()[0]
        return ip_address
    except Exception as e:
        print(f"[!] Failed to get host IP: {e}")
        return None


def ping(dest_addr):
    """Main function to send and receive ICMP packets"""
    try:
        if (platform.system().lower() == 'windows') or (platform.system().lower() == 'linux'):
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    except PermissionError:
        print("Permission denied. Try running as root.")
        return None

    src_addr = get_host_ip()
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
