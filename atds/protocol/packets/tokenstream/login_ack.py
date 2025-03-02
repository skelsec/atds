from dataclasses import dataclass
from enum import IntEnum
from typing import Optional
from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase

class Interface(IntEnum):
    SQL_DFLT = 0    # Server confirms whatever client sent (defaults to SQL_TSQL)
    SQL_TSQL = 1    # TSQL is accepted

@dataclass
class Version:
    major: int
    minor: int
    build_hi: int
    build_low: int

    def to_bytes(self) -> bytes:
        return bytes([
            self.major,
            self.minor,
            self.build_hi,
            self.build_low
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Version':
        if len(data) < 4:
            raise ValueError("Version data must be 4 bytes")
        return cls(
            major=data[0],
            minor=data[1],
            build_hi=data[2],
            build_low=data[3]
        )

class TDS_LOGIN_ACK(TDSTokenStreamBase):
    TOKEN_TYPE = 0xAD  # LOGINACK_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xAD, **kwargs)
        self.length: int = 0
        self.interface: Interface = Interface.SQL_DFLT
        self.tds_version: int = 0
        self.prog_name: str = ""
        self.prog_version: Version = Version(0, 0, 0, 0)

    def from_reader(self, reader: BufferReader) -> 'TDS_LOGIN_ACK':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_LOGIN_ACK.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAD, got {hex(token)}")
        self.length = reader.get_ushort()
        self.interface = Interface(reader.get_byte())
        self.tds_version = reader.get_uint()
        self.prog_name = reader.read_ucs2(reader.get_byte())
        self.prog_version = Version.from_bytes(reader.read(4))
        return self
    
    def __str__(self):
        return f"TDS_LOGIN_ACK(length={self.length}, interface={self.interface}, tds_version={self.tds_version}, prog_name={self.prog_name}, prog_version={self.prog_version})"