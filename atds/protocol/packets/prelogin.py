from dataclasses import dataclass
from enum import IntEnum
from typing import List

class PreLoginOptionToken(IntEnum):
    VERSION = 0x00
    ENCRYPTION = 0x01
    INSTANCE = 0x02
    THREADID = 0x03
    MARS = 0x04
    TRACEID = 0x05
    FEDAUTHREQUIRED = 0x06
    NONCEOPT = 0x07
    TERMINATOR = 0xFF

class EncryptMode(IntEnum):
    ENCRYPT_OFF = 0x00          # Encryption is available but off
    ENCRYPT_ON = 0x01           # Encryption is available and on
    ENCRYPT_NOT_SUP = 0x02      # Encryption is not available
    ENCRYPT_REQ = 0x03          # Encryption is required
    ENCRYPT_EXT = 0x20          # Reserved
    # Certificate auth combinations
    ENCRYPT_CLIENT_CERT_OFF = 0x80    # ENCRYPT_CLIENT_CERT | ENCRYPT_OFF
    ENCRYPT_CLIENT_CERT_ON = 0x81     # ENCRYPT_CLIENT_CERT | ENCRYPT_ON
    ENCRYPT_CLIENT_CERT_REQ = 0x83    # ENCRYPT_CLIENT_CERT | ENCRYPT_REQ

@dataclass
class PreLoginOption:
    token: PreLoginOptionToken
    offset: int
    length: int
    data: bytes

    @classmethod
    def create_version(cls, major: int = 0, minor: int = 0, build: int = 0, subbuild: int = 0) -> 'PreLoginOption':
        # VERSION is 6 bytes: major(2), minor(2), build(2)
        data = bytes([
            (major >> 8) & 0xFF, major & 0xFF,
            (minor >> 8) & 0xFF, minor & 0xFF,
            (build >> 8) & 0xFF, build & 0xFF,
        ])
        return cls(PreLoginOptionToken.VERSION, 0, len(data), data)

    @classmethod
    def create_encryption(cls, encryption_mode: EncryptMode) -> 'PreLoginOption':
        # ENCRYPTION is 1 byte
        data = bytes([encryption_mode])
        return cls(PreLoginOptionToken.ENCRYPTION, 0, len(data), data)

    @classmethod
    def create_instance(cls, instance_name: str = '') -> 'PreLoginOption':
        # INSTANCE is variable length, null-terminated UTF-8
        data = instance_name.encode('utf-8') + b'\x00'
        return cls(PreLoginOptionToken.INSTANCE, 0, len(data), data)

    @classmethod
    def create_threadid(cls, thread_id: int) -> 'PreLoginOption':
        # THREADID is 4 bytes
        data = thread_id.to_bytes(4, byteorder='big')
        return cls(PreLoginOptionToken.THREADID, 0, len(data), data)

    @classmethod
    def create_mars(cls, mars_enabled: bool) -> 'PreLoginOption':
        # MARS is 1 byte
        data = bytes([1 if mars_enabled else 0])
        return cls(PreLoginOptionToken.MARS, 0, len(data), data)

    @classmethod
    def create_traceid(cls, trace_id: bytes) -> 'PreLoginOption':
        # TRACEID is 36 bytes
        if len(trace_id) != 36:
            raise ValueError("TRACEID must be exactly 36 bytes")
        return cls(PreLoginOptionToken.TRACEID, 0, len(trace_id), trace_id)

    @classmethod
    def create_fedauthrequired(cls, fed_auth_required: bool) -> 'PreLoginOption':
        # FEDAUTHREQUIRED is 1 byte
        data = bytes([1 if fed_auth_required else 0])
        return cls(PreLoginOptionToken.FEDAUTHREQUIRED, 0, len(data), data)

    @classmethod
    def create_nonceopt(cls, nonce: bytes) -> 'PreLoginOption':
        # NONCEOPT is 32 bytes
        if len(nonce) != 32:
            raise ValueError("NONCE must be exactly 32 bytes")
        return cls(PreLoginOptionToken.NONCEOPT, 0, len(nonce), nonce)

    def get_version(self) -> tuple[int, int, int, int]:
        """Parse VERSION data into (major, minor, build, subbuild)"""
        if self.token != PreLoginOptionToken.VERSION:
            raise ValueError("Not a VERSION option")
        if len(self.data) != 6:
            raise ValueError("Invalid VERSION data length")
        major = int.from_bytes(self.data[0:2], byteorder='big')
        minor = int.from_bytes(self.data[2:4], byteorder='big')
        build = int.from_bytes(self.data[4:6], byteorder='big')
        return (major, minor, build, 0)  # subbuild is always 0

    def get_encryption(self) -> EncryptMode:
        """Parse ENCRYPTION data"""
        if self.token != PreLoginOptionToken.ENCRYPTION:
            raise ValueError("Not an ENCRYPTION option")
        if len(self.data) != 1:
            raise ValueError("Invalid ENCRYPTION data length")
        return EncryptMode(self.data[0])

    # Add similar getters for other option types as needed

class TDS_PRELOGIN:
    def __init__(self) -> None:
        self.options: List[PreLoginOption] = []

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_PRELOGIN':
        if len(data) < 5:  # Minimum size: 1 token + 2 offset + 2 length
            raise ValueError("PreLogin data too short")

        packet = TDS_PRELOGIN()
        pos = 0
        
        # First pass: read all headers until TERMINATOR
        while pos < len(data):
            token = PreLoginOptionToken(data[pos])
            if token == PreLoginOptionToken.TERMINATOR:
                break
                
            if pos + 5 > len(data):
                raise ValueError("Incomplete PreLogin option header")
                
            offset = int.from_bytes(data[pos+1:pos+3], byteorder='big')
            length = int.from_bytes(data[pos+3:pos+5], byteorder='big')
            
            # Validate offset and length
            if offset + length > len(data):
                raise ValueError(f"Option data extends beyond packet: token={token}, offset={offset}, length={length}")
            
            option_data = data[offset:offset+length]
            packet.options.append(PreLoginOption(token, offset, length, option_data))
            
            pos += 5  # Move to next option header

        # Verify VERSION is first token as required by spec
        if not packet.options or packet.options[0].token != PreLoginOptionToken.VERSION:
            raise ValueError("VERSION must be the first PreLogin option")

        return packet 

    def to_bytes(self) -> bytes:
        if not self.options:
            return bytes([PreLoginOptionToken.TERMINATOR])

        # Verify VERSION is first token
        if self.options[0].token != PreLoginOptionToken.VERSION:
            raise ValueError("VERSION must be the first PreLogin option")

        # Calculate the offset for the first data section
        # Header section: 5 bytes per option + 1 byte terminator
        current_offset = (len(self.options) * 5) + 1

        # First pass: build headers with correct offsets
        headers = bytearray()
        data_section = bytearray()
        
        for option in self.options:
            # Add token, offset, and length to headers
            headers.extend([
                option.token,
                (current_offset >> 8) & 0xFF,  # offset high byte
                current_offset & 0xFF,         # offset low byte
                (len(option.data) >> 8) & 0xFF,  # length high byte
                len(option.data) & 0xFF          # length low byte
            ])
            
            # Add data to data section
            data_section.extend(option.data)
            
            # Update offset for next option
            current_offset += len(option.data)

        # Add terminator to headers
        headers.append(PreLoginOptionToken.TERMINATOR)

        # Combine headers and data
        return bytes(headers + data_section) 

    def __str__(self):
        # please print each option in a readable format
        return "\n".join([str(option) for option in self.options])

    def get_option(self, token: PreLoginOptionToken) -> PreLoginOption | None:
        """
        Get a PreLoginOption by its token.
        Returns None if the option doesn't exist.
        """
        for option in self.options:
            if option.token == token:
                return option
        return None
