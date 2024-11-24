import socket
import os
import platform
import time
import struct

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
    print(dest_addr)
    identifier = os.getpid() & 0xFFFF
    send_ping(sock, src_addr, dest_addr, identifier)
    sock.settimeout(1)
    try:
        while True:
            response = sock.recv(1024)
            recv_time = time.time()

            # Verifica se o pacote recebido é ICMP
            eth_type = struct.unpack("!H", response[12:14])[0]
            if eth_type != 0x0800:  # IPv4
                continue

            # Verifica o cabeçalho IP
            ip_header = response[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            if src_ip != dest_addr or dst_ip != src_addr:
                continue

            # Verifica o cabeçalho ICMP
            icmp_header = response[34:42]
            icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])
            if icmp_type == 0 and icmp_code == 0:  # Echo Reply
                sock.close()
                return True
    except socket.timeout:
        print(f'timeout {dest_addr}')
        sock.close()
        return False
    except Exception as e:
        print(e)
        sock.close()
        return False


def ping_host(ip):
    """Wrapper function to ping a host"""
    return ip, ping(ip)
