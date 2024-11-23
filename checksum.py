def checksum(source_string):
    """Calculate the checksum of the given data."""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    # Sum all 16-bit words
    while count < count_to:
        this_val = source_string[count] + (source_string[count + 1] << 8)
        sum += this_val
        sum &= 0xffffffff  # Keep it 32-bit
        count += 2

    # Handle the last byte, if applicable
    if count_to < len(source_string):
        sum += source_string[-1]
        sum &= 0xffffffff

    # Fold to 16 bits and complement
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum
    return answer & 0xffff  # Return only 16 bits
