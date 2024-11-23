import socket
import struct
import datetime
from html import escape


def parse_ethernet_header(packet):
    """Parse Ethernet header."""
    eth_header = struct.unpack("!6s6sH", packet[:14])
    eth_protocol = socket.ntohs(eth_header[2])
    return eth_protocol


def parse_ip_header(packet):
    """Parse IP header."""
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    return protocol, src_ip, dest_ip


def parse_dns(packet):
    """Parse DNS packets."""
    udp_header = packet[34:42]
    dns_data = packet[42:]
    try:
        query_name = ''
        i = 0
        while True:
            length = dns_data[i]
            if length == 0:
                break
            query_name += dns_data[i + 1:i + 1 + length].decode() + '.'
            i += length + 1
        return query_name.rstrip('.')
    except Exception:
        return None


def parse_http(packet):
    """Parse HTTP packets."""
    http_data = packet[54:]
    try:
        http_payload = http_data.decode(errors="ignore")
        if "Host:" in http_payload:
            lines = http_payload.split("\r\n")
            for line in lines:
                if line.startswith("Host:"):
                    return line.split(":")[1].strip()
    except Exception:
        return None


def generate_html_log(entries):
    """Generate HTML log file."""
    with open("web_history.html", "w") as f:
        f.write("<html><head><title>Web History</title></head><body>")
        f.write("<h1>Web History Log</h1><table border='1'>")
        f.write("<tr><th>Date</th><th>IP</th><th>Host</th><th>URL</th></tr>")
        for entry in entries:
            f.write(f"<tr><td>{escape(entry['date'])}</td>")
            f.write(f"<td>{escape(entry['ip'])}</td>")
            f.write(f"<td>{escape(entry['host'])}</td>")
            f.write(f"<td>{escape(entry['url'])}</td></tr>")
        f.write("</table></body></html>")


def sniff():
    """Sniff packets and analyze DNS/HTTP."""
    sniffer = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    entries = []
    try:
        while True:
            packet = sniffer.recvfrom(65565)[0]
            eth_protocol = parse_ethernet_header(packet)

            # Process only IPv4
            if eth_protocol == 0x0800:
                protocol, src_ip, dest_ip = parse_ip_header(packet)

                if protocol == 17:  # UDP (DNS)
                    query = parse_dns(packet)
                    if query:
                        entries.append({
                            "date": str(datetime.datetime.now()),
                            "ip": src_ip,
                            "host": query,
                            "url": query
                        })

                elif protocol == 6:  # TCP (HTTP)
                    host = parse_http(packet)
                    if host:
                        entries.append({
                            "date": str(datetime.datetime.now()),
                            "ip": src_ip,
                            "host": host,
                            "url": f"http://{host}"
                        })

                if len(entries) % 10 == 0:  # Save periodically
                    generate_html_log(entries)
    except KeyboardInterrupt:
        print("Stopping sniffing...")
        generate_html_log(entries)


if __name__ == "__main__":
    sniff()
