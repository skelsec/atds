from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

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

class TDS_INFO:
    TOKEN_TYPE = 0xAB  # INFO_TOKEN

    def __init__(self) -> None:
        self.length: int = 0
        self.number: int = 0
        self.state: int = 0
        self.class_: InfoClass = InfoClass.GENERAL
        self.message: str = ""
        self.server_name: str = ""
        self.proc_name: str = ""
        self.line_number: int = 0

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_INFO':
        if len(data) < 8:  # Minimum: token(1) + length(2) + number(4) + state(1)
            raise ValueError("INFO data too short")

        # Verify token type
        if data[0] != TDS_INFO.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAB, got {hex(data[0])}")

        packet = TDS_INFO()
        pos = 1  # Start after token

        # Parse length (2 bytes)
        packet.length = int.from_bytes(data[pos:pos+2], byteorder='little')
        if len(data) < packet.length + 1:  # +1 for token byte
            raise ValueError("Data shorter than specified length")
        pos += 2

        # Parse info number (4 bytes)
        packet.number = int.from_bytes(data[pos:pos+4], byteorder='little')
        pos += 4

        # Parse state (1 byte)
        packet.state = data[pos]
        pos += 1

        # Parse class (1 byte)
        packet.class_ = InfoClass(data[pos])
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

        return packet