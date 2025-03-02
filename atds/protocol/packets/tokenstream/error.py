from enum import IntEnum
from atds.tds.utils import BufferReader
import io
from atds.tds import tds_base
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class ErrorSeverity(IntEnum):
    """Error severity class levels"""
    INFORMATIONAL = 0        # 0-9: Informational messages
    INFO_10 = 10            # Special informational messages
    MISSING_OBJECT = 11     # Object/entity does not exist
    SPECIAL_LOCKING = 12    # Special locking errors
    DEADLOCK = 13          # Transaction deadlock errors
    SECURITY = 14          # Permission denied, security errors
    SYNTAX = 15            # SQL syntax errors
    USER_ERROR = 16        # General user-correctable errors
    RESOURCE = 17          # Resource errors (memory, locks, disk space)
    INTERNAL_SW = 18       # Database Engine software errors
    BATCH_ABORT = 19       # Non-configurable engine limit exceeded
    FATAL_TASK = 20        # Fatal task-level errors
    FATAL_DB = 21          # Fatal database-wide errors
    TABLE_CORRUPT = 22     # Table/index corruption errors
    DB_CORRUPT = 23        # Database corruption errors
    HARDWARE = 24          # Media/hardware failure

class TDS_ERROR(TDSTokenStreamBase):
    TOKEN_TYPE = 0xAA  # ERROR_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xAA, **kwargs)
        self.number: int = 0
        self.state: int = 0
        self.severity: ErrorSeverity = ErrorSeverity.INFORMATIONAL
        self.message: str = ""
        self.server_name: str = ""
        self.proc_name: str = ""
        self.line_number: int = 0
        self.length: int = 0

    @property
    def as_exception(self) -> Exception:
        from atds.common.exceptions import TDSError
        return TDSError(self)

    def from_reader(self, reader: BufferReader) -> 'TDS_ERROR':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_ERROR.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAA, got {hex(token)}")
        self.length = reader.get_smallint()
        self.number = reader.get_int()
        self.state = reader.get_byte()
        self.severity = ErrorSeverity(reader.get_byte())
        self.message = reader.read_ucs2(reader.get_smallint())
        self.server_name = reader.read_ucs2(reader.get_byte())
        self.proc_name = reader.read_ucs2(reader.get_byte())
        self.line_number = reader.get_int() if tds_base.IS_TDS72_PLUS(self.tds_version) else reader.get_smallint()
        return self

    def pprint(self):
        return f"[{self.server_name}][{self.proc_name}] {self.message}"
    
    def __str__(self):
        return f"TDS_ERROR(length={self.length}, number={self.number}, state={self.state}, severity={self.severity}, message={self.message}, server_name={self.server_name}, proc_name={self.proc_name}, line_number={self.line_number})"