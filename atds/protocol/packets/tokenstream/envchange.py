from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union

class EnvChangeType(IntEnum):
    """Environment change types"""
    DATABASE = 1                # Database changed
    LANGUAGE = 2               # Language changed
    CHARSET = 3                # Character set changed
    PACKET_SIZE = 4            # Packet size changed
    UNICODE_SORT_LOCAL = 5     # Unicode data sorting local id
    UNICODE_SORT_FLAGS = 6     # Unicode data sorting comparison flags
    SQL_COLLATION = 7          # SQL Collation
    BEGIN_TXN = 8              # Begin Transaction
    COMMIT_TXN = 9             # Commit Transaction
    ROLLBACK_TXN = 10          # Rollback Transaction
    ENLIST_DTC_TXN = 11        # Enlist DTC Transaction
    DEFECT_TXN = 12            # Defect Transaction
    DB_MIRRORING = 13          # Database Mirroring Partner
    PROMOTE_TXN = 15           # Promote Transaction
    TXN_MANAGER_ADDR = 16      # Transaction Manager Address
    TXN_ENDED = 17             # Transaction Ended
    RESET_ACK = 18             # Reset Connection Acknowledgement
    USER_INSTANCE = 19         # User Instance Name
    ROUTING = 20               # Routing Information

@dataclass
class RoutingData:
    """Type 20 specific routing data"""
    protocol: int              # Must be 0 (TCP-IP)
    port: int                  # TCP port number (cannot be 0)
    alternate_server: str      # Server name

class TDS_ENVCHANGE:
    TOKEN_TYPE = 0xE3  # ENVCHANGE_TOKEN

    def __init__(self) -> None:
        self.length: int = 0
        self.type: EnvChangeType = EnvChangeType.DATABASE
        self.new_value: Union[str, bytes, RoutingData, None] = None
        self.old_value: Union[str, bytes, None] = None

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_ENVCHANGE':
        if len(data) < 4:  # Minimum: token(1) + length(2) + type(1)
            raise ValueError("ENVCHANGE data too short")

        # Verify token type
        if data[0] != TDS_ENVCHANGE.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xE3, got {hex(data[0])}")

        packet = TDS_ENVCHANGE()
        pos = 1  # Start after token

        # Parse length (2 bytes)
        packet.length = int.from_bytes(data[pos:pos+2], byteorder='little')
        if len(data) < packet.length + 3:  # +3 for token and length
            raise ValueError("Data shorter than specified length")
        pos += 2

        # Parse type (1 byte)
        packet.type = EnvChangeType(data[pos])
        pos += 1

        # Parse values based on type
        if packet.type == EnvChangeType.ROUTING:
            # Special handling for routing data
            value_len = int.from_bytes(data[pos:pos+2], byteorder='little')
            pos += 2
            
            protocol = data[pos]
            if protocol != 0:  # Must be TCP-IP
                raise ValueError("Invalid protocol: must be 0 (TCP-IP)")
            pos += 1
            
            port = int.from_bytes(data[pos:pos+2], byteorder='little')
            if port == 0:
                raise ValueError("Invalid port: cannot be 0")
            pos += 2
            
            # Parse alternate server as US_VARCHAR
            server_len = int.from_bytes(data[pos:pos+2], byteorder='little')
            pos += 2
            alternate_server = data[pos:pos+server_len*2].decode('utf-16-le')
            
            packet.old_value = None
            packet.new_value = RoutingData(protocol, port, alternate_server)
            
        else:
            # Handle other types according to their format
            if packet.type in {EnvChangeType.SQL_COLLATION, 
                             EnvChangeType.BEGIN_TXN, EnvChangeType.COMMIT_TXN,
                             EnvChangeType.ROLLBACK_TXN, EnvChangeType.ENLIST_DTC_TXN,
                             EnvChangeType.DEFECT_TXN, EnvChangeType.PROMOTE_TXN,
                             EnvChangeType.TXN_MANAGER_ADDR}:
                # B_VARBYTE format
                old_len = data[pos]
                pos += 1
                packet.old_value = data[pos:pos+old_len] if old_len > 0 else None
                pos += old_len
                
                new_len = data[pos]
                pos += 1
                packet.new_value = data[pos:pos+new_len] if new_len > 0 else None
                
            else:
                # B_VARCHAR format
                old_len = data[pos]
                pos += 1
                packet.old_value = data[pos:pos+old_len*2].decode('utf-16-le') if old_len > 0 else None
                pos += old_len * 2
                
                new_len = data[pos]
                pos += 1
                packet.new_value = data[pos:pos+new_len*2].decode('utf-16-le') if new_len > 0 else None

        return packet