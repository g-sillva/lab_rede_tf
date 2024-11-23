import socket
import struct
import time
import threading

activeDevices = []
notActiveDevicesCount = 0
lock = threading.Lock()


def discover(network, waitingTime):
    ep = network.split('/')
    mask = int(ep[1])
    numHosts = (2 ** (32 - mask)) - 2
    ar = ep[0].split('.')
    start = int(ar[3]) + 1
    end = start + numHosts

    threads = []
    for i in range(start, end):
        ip = f"{ar[0]}.{ar[1]}.{ar[2]}.{i}"
        thread = threading.Thread(target=send_packet, args=(ip, waitingTime))
        threads.append(thread)
        thread.start()

    # Espera todas as threads terminarem
    for thread in threads:
        thread.join()


def send_packet(target_ip, waitingTime):
    global notActiveDevicesCount, activeDevices

    try:
        # Criar socket RAW com AF_PACKET
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # Interface de rede a ser usada (ajuste conforme necessário)
        s.bind(("eth0", 0))

        # Criar cabeçalhos Ethernet, IP e ICMP
        eth_header = EthernetHeader().pack()
        ip_header = IpHeader("192.168.0.153", target_ip, ttl=64).pack()
        icmp_packet = create_icmp_packet()

        # Montar o pacote completo
        full_packet = eth_header + ip_header + icmp_packet

        send_time = time.time()
        s.send(full_packet)  # Enviar o pacote

        # Aguardar resposta
        s.settimeout(waitingTime)
        while True:
            response = s.recv(1024)
            recv_time = time.time()

            # Verifica se o pacote recebido é ICMP
            eth_type = struct.unpack("!H", response[12:14])[0]
            if eth_type != 0x0800:  # IPv4
                continue

            # Verifica o cabeçalho IP
            ip_header = response[14:34]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            if src_ip != target_ip or dst_ip != "192.168.0.153":
                continue

            # Verifica o cabeçalho ICMP
            icmp_header = response[34:42]
            icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])
            if icmp_type == 0 and icmp_code == 0:  # Echo Reply
                with lock:
                    activeDevices.append(
                        {"ip": target_ip, "responseTime": (recv_time - send_time) * 1000})
                break

    except socket.timeout:
        with lock:
            notActiveDevicesCount += 1
    except Exception as e:
        print(f"Erro ao enviar pacote para {target_ip}: {e}")
    finally:
        s.close()


def create_icmp_packet():
    icmp_type = 8  # Echo request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 1
    icmp_sequence = 1
    icmp_payload = b"Hello, World!"

    # Cabeçalho ICMP inicial sem checksum
    icmp_header = struct.pack(
        "!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)

    # Calcular checksum
    icmp_checksum = calculate_checksum(icmp_header + icmp_payload)

    # Reempacotar o cabeçalho ICMP com checksum correto
    icmp_header = struct.pack(
        "!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)

    return icmp_header + icmp_payload


def calculate_checksum(data):
    checksum = 0
    # Adiciona padding se necessário
    if len(data) % 2 != 0:
        data += b'\x00'

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    # Adiciona carry
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff


class EthernetHeader:
    def __init__(self):
        # MAC de origem (ajuste conforme necessário)
        self.src_mac = "08:00:27:ad:25:87"
        self.dst_mac = "FF:FF:FF:FF:FF:FF"  # MAC de destino (broadcast)
        self.ethertype = 0x0800  # Protocolo IPv4

    def pack(self):
        self.ethertype = 0x0800  # Protocolo IPv4
        src_mac_bytes = bytes.fromhex(self.src_mac.replace(":", ""))
        dst_mac_bytes = bytes.fromhex(self.dst_mac.replace(":", ""))
        return dst_mac_bytes + src_mac_bytes + struct.pack("!H", self.ethertype)


class IpHeader:
    def __init__(self, src_ip, dst_ip, ttl=64):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.total_length = 20 + 8 + \
            len(b"Hello, World!")  # Cabeçalho IP + ICMP
        self.identification = 54321
        self.flags_offset = 0
        self.ttl = ttl
        self.protocol = socket.IPPROTO_ICMP
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.checksum = 0

    def pack(self):
        version_ihl = (self.version << 4) + self.ihl
        src_ip_bytes = socket.inet_aton(self.src_ip)
        dst_ip_bytes = socket.inet_aton(self.dst_ip)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, self.tos, self.total_length, self.identification,
            self.flags_offset, self.ttl, self.protocol, self.checksum,
            src_ip_bytes, dst_ip_bytes
        )

        self.checksum = calculate_checksum(header)
        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, self.tos, self.total_length, self.identification,
            self.flags_offset, self.ttl, self.protocol, self.checksum,
            src_ip_bytes, dst_ip_bytes
        )


def printInfo(totalDiscoveryTime):
    print("\nResultados da Descoberta:")
    print(f"{'IP':<15} {'Tempo de Resposta (ms)'}")
    print("-" * 35)

    for device in activeDevices:
        print(f"{device['ip']:<15} {device['responseTime']:.2f}")

    print("\nResumo:")
    print(f"Dispositivos Ativos: {len(activeDevices)}")
    print(f"Dispositivos Inativos: {notActiveDevicesCount}")
    print(f"Tempo Total de Descoberta: {totalDiscoveryTime:.2f} segundos")


def main():
    network = "192.168.0.0/24"
    waitingTime = 3  # Tempo de espera em segundos

    discoveryStart = time.time()
    discover(network, waitingTime)
    discoveryEnd = time.time()

    totalDiscoveryTime = discoveryEnd - discoveryStart
    printInfo(totalDiscoveryTime)


if __name__ == "__main__":
    main()
