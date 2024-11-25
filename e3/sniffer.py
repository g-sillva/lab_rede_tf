import socket
import struct
import datetime
from html import escape

# Função para validar se o domínio é aceitável


def is_valid_domain(domain):
    """
    Verifica se um domínio é válido com base em uma série de restrições.
    """
    if not domain or len(domain) < 3 or not '.' in domain or 'api' in domain or '-' in domain or domain.startswith('_') or domain.startswith('#') or domain.startswith('(') or 'ssl.' in domain or 'static.' in domain or '.xx.' in domain or 'gateway' in domain or 'www.' in domain or 'emoji' in domain or 'thumb' in domain or 'asset' in domain or 'preview' in domain or 'style' in domain or 'cdn' in domain or 'collector' in domain or 'services.' in domain or 'css' in domain or 'font' in domain or '.js' in domain:
        return False
    return True

# Função para retornar a data e hora atual


def get_current_date():
    """
    Retorna a data e hora atual no formato dd/mm/aaaa hh:mm:ss.
    """
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# Função para verificar se uma nova entrada deve ser adicionada


def should_add_entry(entries, host=None, path=None):
    """
    Decide se deve adicionar uma nova entrada ao log baseado na última entrada.
    """
    if host is None and path is None:
        return False

    if not entries:
        return True

    last_entry = entries[-1]
    if host and last_entry["host"] != host:
        return True

    if path and last_entry["url"] != f"http://{host}{path}":
        return True

    return False

# Função para gerar o log em formato HTML


def generate_html_log(entries):
    """
    Gera um arquivo HTML com as entradas capturadas (data, IP, host e URL).
    """
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

# Função para processar o cabeçalho Ethernet


def parse_ethernet_header(packet):
    """
    Extrai informações do cabeçalho Ethernet e retorna o protocolo.
    """
    eth_header = struct.unpack("!6s6sH", packet[:14])
    eth_protocol = socket.ntohs(eth_header[2])
    return eth_protocol

# Função para processar o cabeçalho IP


def parse_ip_header(packet):
    """
    Extrai informações do cabeçalho IP (protocolo, IP de origem e destino).
    """
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    return protocol, src_ip, dest_ip

# Função para processar dados HTTP


def parse_http(packet):
    """
    Processa pacotes HTTP para extrair o host e o caminho da requisição.
    """
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

            if is_valid_domain(host):
                return host, path

            return host, path
    except Exception:
        return None

# Função para processar pacotes DNS


def parse_dns(packet):
    """
    Extrai e valida o domínio de pacotes DNS.
    """
    udp_header = packet[34:42]
    src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)

    if dest_port != 53 and src_port != 53:  # Verifica se é DNS
        return None

    dns_data = packet[42:]

    if len(dns_data) < 12:
        return None

    transaction_id, flags, questions, answers, authority, additional = struct.unpack(
        "!HHHHHH", dns_data[:12])

    if questions > 0:
        query_data = dns_data[12:]

        domain = ""
        i = 0
        while query_data[i] != 0:
            length = query_data[i]
            domain += query_data[i + 1:i + 1 + length].decode("utf-8") + "."
            i += length + 1

        domain = domain[:-1]  # Remover o ponto final

        if is_valid_domain(domain):
            return domain

        return None

    return None

# Função principal para capturar pacotes


def sniff(target_host):
    """
    Captura pacotes de rede, analisa DNS e HTTP, e gera um log em HTML.
    """
    sniffer = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    entries = []

    try:
        print('[*] Starting sniffing...')
        while True:
            packet = sniffer.recvfrom(65565)[0]
            eth_protocol = parse_ethernet_header(packet)

            # Processa apenas pacotes IPv4
            if eth_protocol == 8:
                protocol, src_ip, dest_ip = parse_ip_header(packet)

                if src_ip != target_host:
                    continue

                if protocol == 6:  # Protocolo TCP
                    dest_port = struct.unpack("!H", packet[36:38])[0]

                    if dest_port == 80:  # HTTP
                        result = parse_http(packet)
                        if not result:
                            continue

                        # Adiciona se o host for diferente do último no mesmo minuto
                        if should_add_entry(entries, host=result[0], path=result[1]):
                            host, path = result

                            if host is None:
                                continue

                            if path is None:
                                path = "/"

                            entries.append({
                                "date": get_current_date(),
                                "ip": src_ip,
                                "host": host,
                                "url": f"http://{host}{path}"
                            })

                elif protocol == 17:  # Protocolo UDP
                    domain = parse_dns(packet)
                    if should_add_entry(entries, host=domain):

                        entries.append({
                            "date": get_current_date(),
                            "ip": src_ip,
                            "host": domain,
                            "url": f"https://{domain}/..."
                        })

                generate_html_log(entries)

    except KeyboardInterrupt:
        print("Stopping sniffing...")
        generate_html_log(entries)
