import socket

def get_local_ip():
    """
    Obtém o endereço IP local associado à interface de rede ativa.
    """
    try:
        # Cria um socket UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Conecta-se a um servidor DNS público (Google) usando o socket UDP
            s.connect(("8.8.8.8", 80))
            # Obtém o endereço IP local associado ao socket
            ip_address = s.getsockname()[0]
        return ip_address  # Retorna o endereço IP local
    except Exception as e:
        print(f"Error: {e}")
        return None  # Retorna None em caso de erro