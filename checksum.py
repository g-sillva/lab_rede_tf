def checksum(source_string):
    """Calcula o checksum do cabeçalho"""
    checksum = 0

    # Se o comprimento da string de entrada for ímpar, adiciona um byte nulo no final
    if len(source_string) % 2 != 0:
        source_string += b'\x00'

    # Itera sobre a string de entrada de 2 bytes em 2 bytes
    for i in range(0, len(source_string), 2):
        # Combina dois bytes consecutivos em uma palavra de 16 bits
        word = (source_string[i] << 8) + source_string[i + 1]
        # Soma a palavra ao checksum
        checksum += word

    # Adiciona os bits de carry para garantir que o checksum fique dentro de 16 bits
    checksum = (checksum >> 16) + (checksum & 0xffff)
    # Adiciona de novo os bits de carry, se houver
    checksum += (checksum >> 16)
    # Retorna o complemento de 1 do checksum finalizado, ainda como um número de 16 bits
    return ~checksum & 0xffff