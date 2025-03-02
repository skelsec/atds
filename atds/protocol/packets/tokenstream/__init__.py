import enum
import traceback
import io
from atds.tds.utils import BufferReader
from atds.tds.tds_base import TDS71
from atds.protocol.packets import TDSPacket

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

class TDSTokenStreamBase:
    def __init__(self, tokentype: TDSTokenType, tds_version: int = TDS71, column_metadata: 'TDS_COLMETADATA' = None):
        self.tokentype = tokentype
        self.tds_version = tds_version
        self.column_metadata = column_metadata
    
    def from_bytes(self, data: bytes) -> 'TDSTokenStreamBase':
        return self.from_buffer(io.BytesIO(data))

    def from_buffer(self, buffer: io.BytesIO) -> 'TDSTokenStreamBase':
        return self.from_reader(BufferReader(buffer))

    def from_reader(self, reader: BufferReader) -> 'TDSTokenStreamBase':
        raise NotImplementedError("Subclasses must implement this method")




from atds.protocol.packets.tokenstream.done import TDS_DONE, TDS_DONEINPROC, TDS_DONEPROC
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



class TDSTokenParser:
    def __init__(self, tds_version: int = TDS71) -> None:
        self.tds_version = tds_version
        self.colmetadata = None
        self.data_buffer = b''

    def from_bytes(self, data: bytes) -> 'TDSTokenParser':
        self.data_buffer += data
        while len(self.data_buffer) > 0:
            
            #print('=============================================')   
            tokendef = self.data_buffer[0]            
            reader = BufferReader(io.BytesIO(self.data_buffer))

            #print(f"Token definition: {hex(tokendef)}")
            tokentype = TDSTokenType(tokendef)
            #print(f"Token type: {tokentype}")
            if tokentype not in token_type_map or token_type_map[tokentype] is None:
                raise ValueError(f"Token type {tokentype} not implemented")
            
            try:
                #print('buffer before: ', self.data_buffer)
                obj = token_type_map[tokentype](tds_version=self.tds_version, column_metadata=self.colmetadata)
                res = obj.from_reader(reader)
                self.data_buffer = self.data_buffer[reader.buffer.tell():]
            except ClosedConnectionError:
                #traceback.print_exc()
                #print("Want more data")
                break
            if tokentype == TDSTokenType.COLMETADATA:
                self.colmetadata = res
            #print(f"Token result: {res}")
            #print(f"Data after token: {self.data_buffer}")
            yield tokentype, res
            
            

        
        
token_type_map = {
    TDSTokenType.ERROR: TDS_ERROR,
    TDSTokenType.RETURNSTATUS: TDS_RETURNSTATUS,
    TDSTokenType.INFO: TDS_INFO,
    TDSTokenType.LOGINACK: TDS_LOGIN_ACK,
    TDSTokenType.ENVCHANGE: TDS_ENVCHANGE,
    TDSTokenType.DONEINPROC: TDS_DONEINPROC,
    TDSTokenType.DONEPROC: TDS_DONEPROC,
    TDSTokenType.ORDER: TDS_ORDER,
    TDSTokenType.ROW: TDS_ROW,
    TDSTokenType.COLMETADATA: TDS_COLMETADATA,
    TDSTokenType.DONE: TDS_DONE,
    TDSTokenType.SSPI: TDS_SSPI,

}

