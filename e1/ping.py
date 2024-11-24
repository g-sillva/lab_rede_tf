import socket
import os
import platform
import struct
import time

from e1.icmp import send_ping


def get_local_ip():
    """Get the local IP address of the machine"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
    return local_ip


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
    identifier = os.getpid() & 0xFFFF

    send_ping(sock, src_addr, dest_addr, identifier)
    start_time = time.time()
    sock.settimeout(1)

    try:
        while True:
            response = sock.recv(1024)
            eth_type = struct.unpack("!H", response[12:14])[0]
            if eth_type != 0x0800:
                continue

            ip_header = response[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            if src_ip != dest_addr or dst_ip != src_addr:
                continue

            icmp_header = response[34:42]
            icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])
            if icmp_type == 0 and icmp_code == 0:
                end_time = time.time()
                elapsed_time = (end_time - start_time) * 1000
                sock.close()
                return elapsed_time
    except socket.timeout:
        sock.close()
        return -1
    except Exception as e:
        sock.close()
        return -1


def ping_host(ip):
    """Wrapper function to ping a host"""
    return ip, ping(ip)
