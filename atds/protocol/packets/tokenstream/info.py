from enum import IntEnum
from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
from atds.tds import tds_base



class InfoClass(IntEnum):
    """Info class levels (severity < 10 indicates informational message)"""
    GENERAL = 0        # General informational message
    CONNECT = 1        # Connection related
    QUERY = 2          # Query related
    TRANSACTION = 3    # Transaction related
    CURSOR = 4         # Cursor related
    SECURITY = 5       # Security related
    SCHEMA = 6         # Schema related
    BACKUP = 7         # Backup/Restore related
    CONFIG = 8         # Configuration related
    MISC = 9           # Miscellaneous informational

class TDS_INFO(TDSTokenStreamBase):
    TOKEN_TYPE = 0xAB  # INFO_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xAB, **kwargs)
        self.length: int = 0
        self.number: int = 0
        self.state: int = 0
        self.class_: InfoClass = InfoClass.GENERAL
        self.message: str = ""
        self.server_name: str = ""
        self.proc_name: str = ""
        self.line_number: int = 0

    def from_reader(self, reader: BufferReader) -> 'TDS_INFO':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_INFO.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAA, got {hex(token)}")
        self.length = reader.get_smallint()
        self.number = reader.get_int()
        self.state = reader.get_byte()
        self.severity = reader.get_byte()
        self.message = reader.read_ucs2(reader.get_smallint())
        self.server_name = reader.read_ucs2(reader.get_byte())
        self.proc_name = reader.read_ucs2(reader.get_byte())
        self.line_number = reader.get_int() if tds_base.IS_TDS72_PLUS(self.tds_version) else reader.get_smallint()
        return self

    def pprint(self):
        return f"[{self.server_name}][{self.proc_name}] {self.message}"

    def __str__(self):
        return f"TDS_INFO(length={self.length}, number={self.number}, state={self.state}, class_={self.class_}, message={self.message}, server_name={self.server_name}, proc_name={self.proc_name}, line_number={self.line_number})"