import socket
import os
import platform
import subprocess

from e1.icmp import send_ping, receive_ping


def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Attempt to get IP using a dummy UDP connection
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass

    # Fallback: Use the system's default route to determine the IP
    try:
        result = subprocess.check_output(
            ["ip", "route", "get", "1.1.1.1"], encoding="utf-8"
        )
        for line in result.splitlines():
            if "src" in line:
                return line.split("src")[1].strip().split()[0]
    except Exception:
        pass

    # Final fallback: Loopback address if all else fails
    return "127.0.0.1"


def ping(dest_addr):
    """Main function to send and receive ICMP packets."""
    try:
        if platform.system().lower() == 'linux':
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            sock.bind(('eth0', 0))

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
    print(src_addr)
    identifier = os.getpid() & 0xFFFF
    send_ping(sock, src_addr, dest_addr, identifier)

    is_alive = receive_ping(sock, identifier, dest_addr)
    sock.close()
    return is_alive


def ping_host(ip):
    """Wrapper function to ping a host"""
    return ip, ping(ip)
