import enum


class TDSStatus(enum.IntFlag):
    NORMAL = 0x00                      # Normal message
    EOM = 0x01                         # End of message - last packet in request
    IGNORE = 0x02                      # Ignore this event (must be set with EOM)
    RESETCONNECTION = 0x08             # Reset connection before processing (TDS 7.1+)
    RESETCONNECTIONSKIPTRAN = 0x10     # Reset connection but keep transaction state (TDS 7.3+)

    @classmethod
    def from_byte(cls, value: int) -> 'TDSStatus':
        # Filter out any undefined bits as per spec: "All other bits are not used and MUST be ignored"
        valid_bits = value & 0x1B  # 0x1B = 00011011 (only bits 0,1,3,4 are valid)
        return cls(valid_bits)

class TDSPacketType(enum.Enum):
    SQL_BATCH = 1                      # SQL batch
    PRE_TDS7_LOGIN = 2                 # Pre-TDS7 Login
    RPC = 3                            # RPC
    TABULAR_RESULT = 4                 # Tabular result
    ATTENTION = 6                      # Attention signal
    BULK_LOAD = 7                      # Bulk load data
    FEDERATED_AUTH_TOKEN = 8           # Federated Authentication Token
    UNUSED_9 = 9                       # UNUSED
    UNUSED_10 = 10                     # UNUSED
    UNUSED_11 = 11                     # UNUSED
    UNUSED_12 = 12                     # UNUSED
    UNUSED_13 = 13                     # UNUSED
    TRANSACTION_MANAGER = 14           # Transaction manager request
    UNUSED_15 = 15                     # UNUSED
    TDS7_LOGIN = 16                    # TDS7 Login
    SSPI = 17                          # SSPI
    PRELOGIN = 18                      # Pre-Login

class TDSPacket:
    def __init__(self) -> None:
        self.Type: int = 0
        self.Status: TDSStatus = TDSStatus.NORMAL | TDSStatus.EOM
        self.Length: int = 8  # Default length (header size)
        self.SPID: int = 0
        self.PacketID: int = 0
        self.Window: int = 0
        self.Data: bytes = b''

    @staticmethod
    def from_bytes(data: bytes) -> 'TDSPacket':
        if len(data) < 8:  # Minimum header size
            raise ValueError("Packet data too short")
        
        packet = TDSPacket()
        packet.Type = TDSPacketType(int(data[0]))
        packet.Status = TDSStatus.from_byte(int(data[1]))
        packet.Length = int.from_bytes(data[2:4], byteorder='big')
        packet.SPID = int.from_bytes(data[4:6], byteorder='big')
        packet.PacketID = int(data[6])
        packet.Window = int(data[7])
        packet.Data = data[8:packet.Length] if packet.Length > 8 else b''
        
        return packet

    @staticmethod
    def get_total_length(data: bytes) -> int:
        return int.from_bytes(data[2:4], byteorder='big')
    
    def to_bytes(self):
        """
        Converts TDS packet to bytes.
        Format:
        - Type (1 byte)
        - Status (1 byte)
        - Length (2 bytes) - includes header length
        - SPID (2 bytes)
        - PacketID (1 byte)
        - Window (1 byte)
        - Data (variable)
        """
        total_length = len(self.Data) + 8  # 8 bytes for header
        
        header = bytearray()
        header.append(self.Type.value)
        header.append(self.Status.value)
        header.extend(total_length.to_bytes(2, byteorder='big'))
        header.extend(self.SPID.to_bytes(2, byteorder='big'))
        header.append(self.PacketID)
        header.append(self.Window)
        
        return bytes(header + self.Data)

    def parse_data(self):
        # DO not use this method anywhere else besides prelogin and login
        if self.Type in packet_type_map:
            # Get the appropriate class for this packet type
            data_class = packet_type_map[self.Type]
            if data_class is not None:
                # Create an instance and parse the data
                if self.Type == TDSPacketType.TABULAR_RESULT:
                    tp = TDSTokenParser()
                    for tokentype, token in tp.from_bytes(self.Data):
                        # only one token in tabular result at this point
                        return self.Type, tokentype, token
                parsed_data = data_class.from_bytes(self.Data)
                return self.Type, None, parsed_data
        else:
            print(f"Unknown packet type: {self.Type}")
            
        # Return raw bytes for unknown packet types or types without parsers
        return self.Type, None, self.Data
    
    def __str__(self):
        try:
            parsed_data = self.parse_data()
        except Exception as e:
            parsed_data = None
        if parsed_data is not None:
            return f"TDSPacket(Type={self.Type}, Status={self.Status}, Length={self.Length}, SPID={self.SPID}, PacketID={self.PacketID}, Window={self.Window}, Data={parsed_data})"
        else:
            return f"TDSPacket(Type={self.Type}, Status={self.Status}, Length={self.Length}, SPID={self.SPID}, PacketID={self.PacketID}, Window={self.Window}, Data={self.Data})"

from atds.protocol.packets.prelogin import TDS_PRELOGIN
from atds.protocol.packets.tokenstream import TDSTokenParser
# Map packet types to their corresponding data objects
packet_type_map = {
    TDSPacketType.PRELOGIN: TDS_PRELOGIN,
    TDSPacketType.ATTENTION: None,
    TDSPacketType.SQL_BATCH: None, 
    TDSPacketType.TABULAR_RESULT: TDSTokenParser,
    TDSPacketType.BULK_LOAD: None,
    TDSPacketType.FEDERATED_AUTH_TOKEN: None,
    TDSPacketType.TRANSACTION_MANAGER: None,
    TDSPacketType.TDS7_LOGIN: None,
    TDSPacketType.SSPI: None,
    TDSPacketType.PRE_TDS7_LOGIN: None
}