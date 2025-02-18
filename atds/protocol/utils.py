def read_us_varbyte(data: bytes) -> tuple[int, bytes]:
    """Read a US_VARBYTE (variable-length byte array with USHORT length prefix).
    
    Args:
        data: Bytes to read from
        
    Returns:
        Tuple of (bytes consumed, byte array)
    """
    # Read USHORT (2 bytes) length prefix
    length = int.from_bytes(data[0:2], byteorder='little', signed=False)
    
    # Read the byte array
    byte_array = data[2:2+length]
    
    # Return total bytes consumed (2 for length + actual data length) and the byte array
    return 2 + length, byte_array 
    