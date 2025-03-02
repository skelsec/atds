from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class TDS_SSPI(TDSTokenStreamBase):
    TOKEN_TYPE = 0xED  # SSPI_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xED, **kwargs)
        self.sspi_buffer = None
        self.length = 0

    def __repr__(self) -> str:
        return f"TDS_SSPI(sspi_buffer={self.sspi_buffer})"

    def from_reader(self, reader: BufferReader) -> 'TDS_SSPI':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_SSPI.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xED, got {hex(token)}")
        self.length = reader.get_ushort()
        self.sspi_buffer = reader.read(self.length)
        return self

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