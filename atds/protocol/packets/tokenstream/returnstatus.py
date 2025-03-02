from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class TDS_RETURNSTATUS(TDSTokenStreamBase):
    TOKEN_TYPE = 0x79  # RETURNSTATUS_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0x79, **kwargs)
        self.value: int = 0  # LONG value, cannot be NULL

    def from_reader(self, reader: BufferReader) -> 'TDS_RETURNSTATUS':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_RETURNSTATUS.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0x79, got {hex(token)}")
        self.value = reader.get_int()
        return self
    
    def __str__(self):
        return f"TDS_RETURNSTATUS(value={self.value})"
