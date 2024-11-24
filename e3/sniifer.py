import socket
import struct
import datetime
from html import escape

def generate_html_log(entries):
  """Generate HTML log file."""
  with open("web_history.html", "w") as f:
      f.write("<html><head><title>Lab Redes - TF</title></head>")
      f.write("<style> * { box-sizing: border-box; padding: 0; margin: 0; font-family: Arial, sans-serif } h1 { margin: 20px 0; font-weight: 400; font-size: 18px; text-align: center; } table { width: 80%; border-collapse: collapse; margin: 20px auto; } tr > th { background-color: #191621; color: #fff; overflow: hidden; font-size: 14px; letter-spacing: 1px; font-weight: 500; } tr > th:first-child { border-top-left-radius: 10px; } tr > th:last-child { border-top-right-radius: 10px; } th, td { padding: 15px; font-size: 14px; text-align: left; color: #3d3d3d; } tr:nth-child(odd) { background-color: #F5F5F5; }</style>")
      f.write("<body><h1>Monitoramento</h1><table>")
      f.write("<tr><th>Data</th><th>IP</th><th>Host</th><th>URL</th></tr>")
      for entry in entries:
          f.write(f"<tr><td>{escape(entry['date'])}</td>")
          f.write(f"<td>{escape(entry['ip'])}</td>")
          f.write(f"<td>{escape(entry['host'])}</td>")
          f.write(f"<td>{escape(entry['url'])}</td></tr>")
      f.write("</table></body></html>")


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
            if host and '.' in host:
                return host, path
    except Exception:
        return None

def parse_tls_sni(packet):
    """Parse SNI from a TLS handshake packet."""
    try:
        tls_handshake_start = 66
        
        if len(packet) < tls_handshake_start + 5:
            return None
        
        handshake_type = packet[tls_handshake_start + 5]  

        if handshake_type == 0x01:  # Client Hello
            extensions_offset = tls_handshake_start + 43

            while extensions_offset < len(packet) - 4:
                extension_type = struct.unpack("!H", packet[extensions_offset:extensions_offset + 2])[0]

                if extension_type == 0x00:  # Extensão SNI
                    sni_length = struct.unpack("!H", packet[extensions_offset + 4:extensions_offset + 6])[0]
                    sni_bytes = packet[extensions_offset + 6:extensions_offset + 6 + sni_length]

                    sni = sni_bytes.decode('utf-8', errors='ignore')

                    # Check if the SNI is a domain name
                    if not ".com" in sni and not ".net" in sni:
                        return None

                    # Clean up the SNI
                    sni = sni.strip().rstrip('\x00')

                    if sni:
                        return sni
                else:
                    extensions_offset += 1
        
    except Exception as e:
        print(f"Error parsing TLS SNI: {e}")
        return None


def sniff(target_host):
    """Sniff packets and analyze DNS/HTTP/HTTPS."""
    sniffer = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    entries = []
    try:
        print('[*] Starting sniffing...')
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
                    dest_port = struct.unpack("!H", packet[36:38])[0]

                    if dest_port == 80: # HTTP
                        result = parse_http(packet)
                        if result:
                            host, path = result
                            entries.append({
                                "date": str(datetime.datetime.now()),
                                "ip": src_ip,
                                "host": host,
                                "url": f"http://{host}{path}"
                            })

                    elif dest_port == 443: # HTTPS
                        sni = parse_tls_sni(packet)
                        if sni:
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
