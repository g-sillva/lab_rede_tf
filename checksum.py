def checksum(source_string):
    """Calcula o checksum do cabeçalho"""
    checksum = 0
    if len(source_string) % 2 != 0:
        source_string += b'\x00'

    for i in range(0, len(source_string), 2):
        word = (source_string[i] << 8) + source_string[i + 1]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff
