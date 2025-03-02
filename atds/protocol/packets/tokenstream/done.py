from dataclasses import dataclass
from enum import IntFlag
from typing import Optional
from atds.tds.utils import BufferReader
import io
from atds.tds import tds_base
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class DoneStatus(IntFlag):
    """Status flags for DONE token"""
    DONE_FINAL = 0x000        # This DONE is the final DONE in the request
    DONE_MORE = 0x001         # More data streams to follow
    DONE_ERROR = 0x002        # Error occurred on current SQL statement
    DONE_INXACT = 0x004       # Transaction in progress
    DONE_COUNT = 0x010        # DoneRowCount is valid
    DONE_ATTN = 0x020         # Server acknowledgement of client ATTENTION
    DONE_SRVERROR = 0x100     # Severe error, discard result set

class TDS_DONE(TDSTokenStreamBase):
    TOKEN_TYPE = 0xFD  # DONE_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xFD, **kwargs)
        self.status: DoneStatus = DoneStatus.DONE_FINAL
        self.cur_cmd: int = 0
        self.row_count: int = 0  # LONG or ULONGLONG depending on TDS version
        self.length: int = 0

    def from_reader(self, reader: BufferReader) -> 'TDS_DONE':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_DONE.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xFD, got {hex(token)}")
        packet = TDS_DONE()
        packet.status = DoneStatus(reader.get_ushort())
        packet.cur_cmd = reader.get_ushort()
        packet.row_count = reader.get_int8() if tds_base.IS_TDS72_PLUS(self.tds_version) else reader.get_int()
        packet.length = reader.buffer.tell()
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


class TDS_DONEINPROC(TDSTokenStreamBase):
    TOKEN_TYPE = 0xFF  # DONEINPROC_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xFF, **kwargs)
        self.status: DoneStatus = DoneStatus.DONE_FINAL
        self.cur_cmd: int = 0
        self.row_count: int = 0
        self.length: int = 0

    def from_reader(self, reader: BufferReader) -> 'TDS_DONEINPROC':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_DONEINPROC.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xFE, got {hex(token)}")
        self.status = DoneStatus(reader.get_ushort())
        self.cur_cmd = reader.get_ushort()
        self.row_count = reader.get_int8() if tds_base.IS_TDS72_PLUS(self.tds_version) else reader.get_int()
        self.length = reader.buffer.tell()
        return self

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

class TDS_DONEPROC(TDSTokenStreamBase):
    TOKEN_TYPE = 0xFE  # DONEPROC_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xFE, **kwargs)
        self.status: DoneStatus = DoneStatus.DONE_FINAL
        self.cur_cmd: int = 0
        self.row_count: int = 0
        self.length: int = 0

    def from_reader(self, reader: BufferReader) -> 'TDS_DONEPROC':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_DONEPROC.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xFF, got {hex(token)}")
        self.status = DoneStatus(reader.get_ushort())
        self.cur_cmd = reader.get_ushort()
        self.row_count = reader.get_int8() if tds_base.IS_TDS72_PLUS(self.tds_version) else reader.get_int()
        self.length = reader.buffer.tell()
        return self

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
