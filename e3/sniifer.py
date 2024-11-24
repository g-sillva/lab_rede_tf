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
            host = None
            path = None
            for line in lines:
                if line.startswith("Host:"):
                    host = line.split(":")[1].strip()
                elif "GET" in line or "POST" in line:
                    parts = line.split(" ")
                    if len(parts) > 1:
                        path = parts[1]
            if host:
                print(host, path)
                return host, path
    except Exception:
        return None

def parse_sni(packet):
    """Parse SNI in HTTPS (SSL/TLS handshake)."""
    ssl_data = packet[54:]
    if len(ssl_data) < 5:
        return None

    if ssl_data[0] == 0x16:  # Handshake type (0x16 = Client Hello)
        print('Handshake!!!')

        handshake_data = ssl_data[5:]

        handshake_length = struct.unpack("!H", handshake_data[:2])[0]
        handshake_data = handshake_data[2:]

        if len(handshake_data) >= handshake_length:
            extensions_offset = 43  # This is a fixed offset for SNI in most handshakes
            if len(handshake_data) > extensions_offset:
                extensions_data = handshake_data[extensions_offset:]

                i = 0
                while i < len(extensions_data):
                    extension_type = struct.unpack("!H", extensions_data[i:i+2])[0]
                    extension_length = struct.unpack("!H", extensions_data[i+2:i+4])[0]

                    if extension_type == 0x00:  # SNI extension type
                        sni_name = extensions_data[i + 4:i + 4 + extension_length].decode(errors='ignore')
                        return sni_name
                    i += 4 + extension_length
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


def sniff(target_host):
    """Sniff packets and analyze DNS/HTTP/HTTPS."""
    sniffer = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    entries = []
    try:
        while True:
            packet = sniffer.recvfrom(65565)[0]
            eth_protocol = parse_ethernet_header(packet)

            # Process only IPv4
            if eth_protocol == 8:
                protocol, src_ip, dest_ip = parse_ip_header(packet)

                if src_ip != target_host:
                    continue

                if protocol == 17:  # UDP (DNS)
                    query = parse_dns(packet)
                    if query:
                        entries.append({
                            "date": str(datetime.datetime.now()),
                            "ip": src_ip,
                            "host": query,
                            "url": query
                        })

                elif protocol == 6:  # TCP (HTTP/HTTPS)
                    # If the packet is on port 80, it's HTTP
                    dest_port = struct.unpack("!H", packet[36:38])[0]
                    if dest_port == 80:
                        result = parse_http(packet)
                        if result:
                            host, path = result
                            entries.append({
                                "date": str(datetime.datetime.now()),
                                "ip": src_ip,
                                "host": host,
                                "url": f"http://{host}{path}"
                            })
                    # If the packet is on port 443, it's HTTPS
                    elif dest_port == 443:
                        sni = parse_sni(packet)
                        if sni:
                            print(sni)
                            entries.append({
                                "date": str(datetime.datetime.now()),
                                "ip": src_ip,
                                "host": sni,
                                "url": f"https://{sni}"
                            })

                generate_html_log(entries)

    except KeyboardInterrupt:
        print("Stopping sniffing...")
        generate_html_log(entries)


if __name__ == "__main__":
    sniff('192.168.0.169')
