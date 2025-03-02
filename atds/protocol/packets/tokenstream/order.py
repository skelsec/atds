from typing import List
from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase

class TDS_ORDER(TDSTokenStreamBase):
    TOKEN_TYPE = 0xA9  # ORDER_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xA9, **kwargs)
        self.length: int = 0
        self.columns: List[int] = []  # List of column numbers in ORDER BY clause

    def from_reader(self, reader: BufferReader) -> 'TDS_ORDER':
        # Verify token type 
        token = reader.get_byte()
        if token != TDS_ORDER.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xA9, got {hex(token)}")
        self.length = reader.get_smallint()
        for _ in range(self.length//2):
            self.columns.append(reader.get_ushort())
        return self