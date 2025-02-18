from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

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

class TDS_ERROR:
    TOKEN_TYPE = 0xAA  # ERROR_TOKEN

    def __init__(self) -> None:
        self.length: int = 0
        self.number: int = 0
        self.state: int = 0
        self.severity: ErrorSeverity = ErrorSeverity.INFORMATIONAL
        self.message: str = ""
        self.server_name: str = ""
        self.proc_name: str = ""
        self.line_number: int = 0

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_ERROR':
        if len(data) < 8:  # Minimum: token(1) + length(2) + number(4) + state(1)
            raise ValueError("ERROR data too short")

        # Verify token type
        if data[0] != TDS_ERROR.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAA, got {hex(data[0])}")

        packet = TDS_ERROR()
        pos = 1  # Start after token

        # Parse length (2 bytes)
        packet.length = int.from_bytes(data[pos:pos+2], byteorder='little')
        if len(data) < packet.length + 1:  # +1 for token byte
            raise ValueError("Data shorter than specified length")
        pos += 2

        # Parse error number (4 bytes)
        packet.number = int.from_bytes(data[pos:pos+4], byteorder='little')
        pos += 4

        # Parse state (1 byte)
        packet.state = data[pos]
        pos += 1

        # Parse class/severity (1 byte)
        packet.severity = ErrorSeverity(data[pos])
        pos += 1

        # Parse message text (US_VARCHAR)
        msg_len = int.from_bytes(data[pos:pos+2], byteorder='little')
        pos += 2
        packet.message = data[pos:pos+msg_len*2].decode('utf-16-le')
        pos += msg_len * 2

        # Parse server name (B_VARCHAR)
        srv_len = data[pos]
        pos += 1
        packet.server_name = data[pos:pos+srv_len*2].decode('utf-16-le')
        pos += srv_len * 2

        # Parse proc name (B_VARCHAR)
        proc_len = data[pos]
        pos += 1
        packet.proc_name = data[pos:pos+proc_len*2].decode('utf-16-le')
        pos += proc_len * 2

        # Parse line number (4 bytes for TDS 7.2+)
        packet.line_number = int.from_bytes(data[pos:pos+4], byteorder='little')
        pos += 4

        return packet
    
    def __str__(self):
        return f"TDS_ERROR(length={self.length}, number={self.number}, state={self.state}, severity={self.severity}, message={self.message}, server_name={self.server_name}, proc_name={self.proc_name}, line_number={self.line_number})"