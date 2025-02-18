from dataclasses import dataclass
from enum import IntFlag
from typing import Optional

class DoneStatus(IntFlag):
    """Status flags for DONE token"""
    DONE_FINAL = 0x000        # This DONE is the final DONE in the request
    DONE_MORE = 0x001         # More data streams to follow
    DONE_ERROR = 0x002        # Error occurred on current SQL statement
    DONE_INXACT = 0x004       # Transaction in progress
    DONE_COUNT = 0x010        # DoneRowCount is valid
    DONE_ATTN = 0x020         # Server acknowledgement of client ATTENTION
    DONE_SRVERROR = 0x100     # Severe error, discard result set

class TDS_DONE:
    TOKEN_TYPE = 0xFD  # DONE_TOKEN

    def __init__(self) -> None:
        self.status: DoneStatus = DoneStatus.DONE_FINAL
        self.cur_cmd: int = 0
        self.row_count: int = 0  # LONG or ULONGLONG depending on TDS version
        self.length: int = 0

    @staticmethod
    def from_bytes(data: bytes, tds_version: float = 7.1) -> 'TDS_DONE':
        if len(data) < 9:  # Minimum: token(1) + status(2) + curcmd(2) + count(4/8)
            raise ValueError("DONE data too short")

        # Verify token type
        if data[0] != TDS_DONE.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xFD, got {hex(data[0])}")

        packet = TDS_DONE()
        pos = 1  # Start after token

        # Parse status (2 bytes, little-endian)
        packet.status = DoneStatus(int.from_bytes(data[pos:pos+2], byteorder='little'))
        pos += 2

        # Parse current command (2 bytes, little-endian)
        packet.cur_cmd = int.from_bytes(data[pos:pos+2], byteorder='little')
        pos += 2

        # Parse row count (4 or 8 bytes depending on TDS version)
        count_size = 8 if tds_version >= 7.2 else 4
        if len(data) < pos + count_size:
            raise ValueError(f"Data too short, needed {count_size} bytes")

        # Only parse row count if DONE_COUNT is set
        if packet.status & DoneStatus.DONE_COUNT:
            packet.row_count = int.from_bytes(
                data[pos:pos+count_size], 
                byteorder='little', 
                signed=count_size == 4  # LONG is signed, ULONGLONG is unsigned
            )
        packet.length = pos + count_size
        return packet

    @property
    def is_final(self) -> bool:
        """Check if this is the final DONE token"""
        return not bool(self.status & DoneStatus.DONE_MORE)

    @property
    def has_error(self) -> bool:
        """Check if an error occurred"""
        return bool(self.status & (DoneStatus.DONE_ERROR | DoneStatus.DONE_SRVERROR))

    @property
    def in_transaction(self) -> bool:
        """Check if a transaction is in progress"""
        return bool(self.status & DoneStatus.DONE_INXACT)

    @property
    def has_count(self) -> bool:
        """Check if row count is valid"""
        return bool(self.status & DoneStatus.DONE_COUNT)

    @property
    def is_attention(self) -> bool:
        """Check if this is an attention acknowledgement"""
        return bool(self.status & DoneStatus.DONE_ATTN)