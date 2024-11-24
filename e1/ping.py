import socket
import os
import time
import platform

from e1.icmp import send_ping, receive_ping


def get_local_ip():
    """Get the local IP address of the machine"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
    return local_ip


def ping(dest_addr):
    """Main function to send and receive ICMP packets."""
    try:
        if platform.system().lower() == 'linux':
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        elif platform.system().lower() == 'windows':
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        else:
            raise OSError("Unsupported platform")

    except PermissionError:
        print("Permission denied. Run the script with elevated privileges (sudo).")
        return False

    src_addr = get_local_ip()
    identifier = os.getpid() & 0xFFFF
    send_ping(sock, src_addr, dest_addr, identifier)

    is_alive = receive_ping(sock, identifier, dest_addr)
    sock.close()
    return is_alive


def ping_host(ip):
    """Wrapper function to ping a host"""
    return ip, ping(ip)
