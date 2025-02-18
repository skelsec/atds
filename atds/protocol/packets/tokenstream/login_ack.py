from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

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

class TDS_LOGIN_ACK:
    TOKEN_TYPE = 0xAD  # LOGINACK_TOKEN

    def __init__(self) -> None:
        self.length: int = 0
        self.interface: Interface = Interface.SQL_DFLT
        self.tds_version: int = 0
        self.prog_name: str = ""
        self.prog_version: Version = Version(0, 0, 0, 0)

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_LOGIN_ACK':
        if len(data) < 3:  # Minimum: token(1) + length(2)
            raise ValueError("LOGIN_ACK data too short")

        # Verify token type
        if data[0] != TDS_LOGIN_ACK.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAD, got {hex(data[0])}")

        packet = TDS_LOGIN_ACK()
        
        # Parse length (2 bytes)
        packet.length = int.from_bytes(data[1:3], byteorder='little')
        
        if len(data) < packet.length + 3:
            raise ValueError("Data shorter than specified length")
        
        pos = 3  # Start after token and length
        
        # Parse interface (1 byte)
        packet.interface = Interface(data[pos])
        pos += 1
        
        # Parse TDS version (4 bytes)
        packet.tds_version = int.from_bytes(data[pos:pos+4], byteorder='little')
        pos += 4
        
        # Parse program name (B_VARCHAR)
        name_length = data[pos]
        pos += 1
        packet.prog_name = data[pos:pos+name_length].decode('utf-16-le')
        pos += name_length
        
        # Parse program version (4 bytes)
        packet.prog_version = Version.from_bytes(data[pos:pos+4])
        pos += 4
        
        return packet
    
    def __str__(self):
        return f"TDS_LOGIN_ACK(length={self.length}, interface={self.interface}, tds_version={self.tds_version}, prog_name={self.prog_name}, prog_version={self.prog_version})"