import enum
from atds.protocol.packets import TDSPacket
from atds.protocol.packets.tokenstream.done import TDS_DONE
from atds.protocol.packets.tokenstream.error import TDS_ERROR
from atds.protocol.packets.tokenstream.returnstatus import TDS_RETURNSTATUS
from atds.protocol.packets.tokenstream.info import TDS_INFO
from atds.protocol.packets.tokenstream.sspi import TDS_SSPI
from atds.protocol.packets.tokenstream.login_ack import TDS_LOGIN_ACK
from atds.protocol.packets.tokenstream.envchange import TDS_ENVCHANGE
from atds.protocol.packets.tokenstream.colmetadata import TDS_COLMETADATA
from atds.protocol.packets.tokenstream.row import TDS_ROW
from atds.protocol.packets.tokenstream.order import TDS_ORDER

from atds.tds.tds_base import ClosedConnectionError

class TDSTokenType(enum.IntEnum):
    ERROR = 0xAA           # Error message
    RETURNSTATUS = 0x79    # Return status
    INFO = 0xAB            # Info message
    LOGINACK = 0xAD        # Login acknowledgment
    ENVCHANGE = 0xE3       # Environment change
    DONEINPROC = 0xFF      # Done in procedure
    DONEPROC = 0xFE        # Done procedure
    ORDER = 0xA9           # Order
    ROW = 0xD1             # Row
    COLMETADATA = 0x81     # Column metadata
    DONE = 0xFD            # Done
    ALTMETADATA = 0x88     # Alt metadata
    ALTROW = 0xD3          # Alt row
    COLINFO = 0xA5         # Column info
    NBCROW = 0xD2          # Nbc row
    OFFSET = 0x78          # Offset
    RETURNVALUE = 0xAC     # Return value
    SSPI = 0xED            # Sspi
    TABNAME = 0xA4          # Tab name

class TDSTokenParser:
    def __init__(self) -> None:
        self.colmetadata = None
        self.data_buffer = b''

    def from_bytes(self, data: bytes) -> 'TDSTokenParser':
        self.data_buffer += data
        while True:
            #print('=============================================')   
            tokendef = self.data_buffer[0]
            if tokendef == 0x00:
                break

            #print(f"Token definition: {hex(tokendef)}")
            tokentype = TDSTokenType(tokendef)
            #print(f"Token type: {tokentype}")
            if tokentype not in token_type_map or token_type_map[tokentype] is None:
                raise ValueError(f"Token type {tokentype} not implemented")
            if tokentype == TDSTokenType.ROW:
                try:
                    res = token_type_map[tokentype].from_bytes(self.data_buffer, self.colmetadata)
                    self.data_buffer = self.data_buffer[res.length+1:] # + 2 = token type(1)
                except ClosedConnectionError:
                    print('more data needed')
                    break
            else:
                res = token_type_map[tokentype].from_bytes(self.data_buffer)
                self.data_buffer = self.data_buffer[res.length+3:] # + 3 = token type(1) + token length(2)
                if tokentype == TDSTokenType.COLMETADATA:
                    self.colmetadata = res
            #print(f"Token result: {res}")
            yield tokentype, res
            
            #print(f"Data after token: {data}")
            if tokentype == TDSTokenType.DONE:
                break
            if len(data) == 0:
                break

        
        
token_type_map = {
    TDSTokenType.ERROR: TDS_ERROR,
    TDSTokenType.RETURNSTATUS: TDS_RETURNSTATUS,
    TDSTokenType.INFO: TDS_INFO,
    TDSTokenType.LOGINACK: TDS_LOGIN_ACK,
    TDSTokenType.ENVCHANGE: TDS_ENVCHANGE,
    TDSTokenType.DONEINPROC: None,
    TDSTokenType.DONEPROC: None,
    TDSTokenType.ORDER: TDS_ORDER,
    TDSTokenType.ROW: TDS_ROW,
    TDSTokenType.COLMETADATA: TDS_COLMETADATA,
    TDSTokenType.DONE: TDS_DONE,
    TDSTokenType.SSPI: TDS_SSPI
}