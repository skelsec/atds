class TDS_SSPI:
    TOKEN_TYPE = 0xED  # SSPI_TOKEN

    def __init__(self, sspi_buffer: bytes, length: int = None) -> None:
        self.sspi_buffer = sspi_buffer
        self.length = len(sspi_buffer) if length is None else length

    def __repr__(self) -> str:
        return f"TDS_SSPI(sspi_buffer={self.sspi_buffer})"

    @staticmethod
    def from_bytes(data: bytes) -> tuple[int, 'TDS_SSPI']:
        # Skip token type byte (0xED)
        pos = 1
        
        # Read SSPI buffer length (2 bytes, little-endian)
        length = int.from_bytes(data[pos:pos+2], byteorder='little', signed=False)
        pos += 2
        
        # Read SSPI buffer
        sspi_buffer = data[pos:pos+length]
        pos += length

        return TDS_SSPI(sspi_buffer, length)

    def to_bytes(self) -> bytes:
        """Serialize SSPI token to bytes.
        
        Returns:
            Bytes representation of the SSPI token
        """
        # Token type (0xED)
        result = bytes([self.TOKEN_TYPE])
        
        # SSPI buffer length as USHORT (2 bytes, little-endian)
        result += len(self.sspi_buffer).to_bytes(2, byteorder='little', signed=False)
        
        # SSPI buffer content
        result += self.sspi_buffer
        
        return result