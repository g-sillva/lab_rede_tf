import socket
import struct
import threading

# Defina o servidor DNS legítimo (pode ser alterado para qualquer servidor DNS de sua escolha)
DNS_SERVER = "8.8.8.8"  # Google DNS

def handle_dns_request(data, addr, sock):
    """
    Intercepta e responde a uma requisição DNS com o IP verdadeiro.
    """
    # Pega o nome do domínio da requisição DNS
    domain_name = parse_dns_request(data)
    print(f"[*] Requisição DNS recebida para: {domain_name}")

    # Encaminha a requisição para o servidor DNS legítimo
    fake_ip = resolve_dns(domain_name)

    # Se não conseguir resolver, retorna um erro
    if not fake_ip:
        print(f"[!] Não foi possível resolver o domínio: {domain_name}")
        return

    print(f"[*] Resolvendo para: {fake_ip}")

    # Cria a resposta DNS com o IP verdadeiro
    response = create_dns_response(data, fake_ip)
    
    # Envia a resposta para a vítima
    sock.sendto(response, addr)

def resolve_dns(domain_name):
    """
    Encaminha a requisição DNS para o servidor legítimo e retorna a resposta.
    """
    try:
        # Envia a requisição DNS para o servidor legítimo
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.settimeout(2)

        # Envia o pedido de resolução DNS (requisição original)
        dns_sock.sendto(create_dns_query(domain_name), (DNS_SERVER, 53))
        
        # Recebe a resposta DNS do servidor legítimo
        data, _ = dns_sock.recvfrom(512)
        dns_sock.close()

        # Extrai o IP real da resposta DNS
        return parse_dns_response(data)
    except socket.timeout:
        print(f"[!] Timeout ao tentar resolver o domínio {domain_name}")
        return None

def parse_dns_request(data):
    """
    Extrai o nome do domínio da requisição DNS.
    """
    index = 12  # Posição inicial após o cabeçalho DNS
    domain_name = ""
    while data[index] != 0:
        length = data[index]
        domain_name += data[index+1:index+1+length].decode("utf-8") + "."
        index += length + 1
    return domain_name[:-1]

def create_dns_query(domain_name):
    """
    Cria a requisição DNS para o servidor DNS legítimo.
    """
    # Cabeçalho da requisição DNS
    transaction_id = b'\x00\x01'  # Identificador de transação
    flags = b'\x01\x00'  # Query
    questions = b'\x00\x01'  # Uma questão
    answer_rr = b'\x00\x00'
    authority_rr = b'\x00\x00'
    additional_rr = b'\x00\x00'

    # Formato da requisição
    query = transaction_id + flags + questions + answer_rr + authority_rr + additional_rr

    # Nome do domínio solicitado
    domain_parts = domain_name.split(".")
    for part in domain_parts:
        query += bytes([len(part)]) + part.encode("utf-8")

    # Adiciona o final do nome de domínio
    query += b"\x00"

    # Tipo A (IPv4) e classe IN
    query += b"\x00\x01"  # Tipo A
    query += b"\x00\x01"  # Classe IN

    return query

def parse_dns_response(data):
    """
    Extrai o IP da resposta DNS.
    """
    # O IP está na parte final da resposta
    ip_bytes = data[-4:]
    return socket.inet_ntoa(ip_bytes)

def create_dns_response(request, fake_ip):
    """
    Cria a resposta DNS com o IP verdadeiro.
    """
    transaction_id = request[:2]
    flags = b"\x81\x80"  # Resposta com sucesso
    questions = b"\x00\x01"
    answer_rr = b"\x00\x01"
    authority_rr = b"\x00\x00"
    additional_rr = b"\x00\x00"

    # IP verdadeiro na resposta DNS
    ip_bytes = socket.inet_aton(fake_ip)

    response = transaction_id + flags + questions + answer_rr + authority_rr + additional_rr
    response += request[12:]  # Mantém a parte da requisição (domínio)
    response += b"\xc0\x0c"  # Nome do domínio no final
    response += b"\x00\x01"  # Tipo A (resposta para IPv4)
    response += b"\x00\x01"  # Classe IN
    response += b"\x00\x00\x00\x3c"  # TTL de 60 segundos
    response += b"\x00\x04"  # Tamanho do dado de resposta (4 bytes para IPv4)
    response += ip_bytes  # O IP verdadeiro

    return response

def start_dns_sniffer():
    """
    Inicia o servidor que intercepta requisições DNS e encaminha para o DNS legítimo.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))

    print("[*] Escutando requisições DNS na porta 53...")

    while True:
        data, addr = sock.recvfrom(512)  # Tamanho máximo de pacote DNS
        if data:
            threading.Thread(target=handle_dns_request, args=(data, addr, sock)).start()

if __name__ == "__main__":
    start_dns_sniffer()
