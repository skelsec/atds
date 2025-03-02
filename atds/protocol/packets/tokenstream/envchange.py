from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union
from atds.tds.utils import BufferReader
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase

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

class TDS_ENVCHANGE(TDSTokenStreamBase):
    TOKEN_TYPE = 0xE3  # ENVCHANGE_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xE3, **kwargs)
        self.type: EnvChangeType = EnvChangeType.DATABASE
        self.new_value: Union[str, bytes, RoutingData, None] = None
        self.old_value: Union[str, bytes, None] = None

    def from_reader(self, reader: BufferReader) -> 'TDS_ENVCHANGE':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_ENVCHANGE.TOKEN_TYPE:
            raise ValueError(f"Inval    id TOKEN_TYPE: expected 0xE3, got {hex(token)}")
        
        self.size = reader.get_smallint()
        # skipping this for now
        reader.skipall(self.size - 3)
        return self




        
        type_id = r.get_byte()
        if type_id == EnvChangeType.SQL_COLLATION:
            size = r.get_byte()
            self.conn.collation = r.get_collation()
            #print("switched collation to %s", self.conn.collation)
            reader.skipall(size - 5)
            # discard old one
            reader.skipall(r.get_byte())
        elif type_id == EnvChangeType.BEGIN_TXN:
            size = r.get_byte()
            assert size == 8
            self.conn.tds72_transaction = r.get_uint8()
            # old val, should be 0
            reader.skipall(r.get_byte())
        elif (
            type_id == EnvChangeType.COMMIT_TXN
            or type_id == EnvChangeType.ROLLBACK_TXN
        ):
            self.conn.tds72_transaction = 0
            # new val, should be 0
            reader.skipall(r.get_byte())
            # old val, should have previous transaction id
            reader.skipall(r.get_byte())
        elif type_id == EnvChangeType.PACKET_SIZE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            new_block_size = int(newval)
            if new_block_size >= 512:
                # Is possible to have a shrink if server limits packet
                # size more than what we specified
                #
                # Reallocate buffer if possible (strange values from server or out of memory) use older buffer */
                self._writer.bufsize = new_block_size
        elif type_id == EnvChangeType.DATABASE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.database = newval
        elif type_id == EnvChangeType.LANGUAGE:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.language = newval
        elif type_id == EnvChangeType.CHARSET:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
            self.conn.env.charset = newval
            remap = {"iso_1": "iso8859-1"}
            self.conn.server_codec = codecs.lookup(remap.get(newval, newval))
        elif type_id == EnvChangeType.DB_MIRRORING:
            newval = r.read_ucs2(r.get_byte())
            r.read_ucs2(r.get_byte())
        elif type_id == EnvChangeType.LCID:
            lcid = int(r.read_ucs2(r.get_byte()))
            self.conn.server_codec = codecs.lookup(lcid2charset(lcid))
            r.read_ucs2(r.get_byte())
        elif type_id == EnvChangeType.UNICODE_SORT_FLAGS:
            r.read_ucs2(r.get_byte())
            comp_flags = r.read_ucs2(r.get_byte())
            self.conn.comp_flags = comp_flags
        elif type_id == EnvChangeType.ROUTING:
            # routing
            r.get_usmallint()
            protocol = r.get_byte()
            protocol_property = r.get_usmallint()
            alt_server = r.read_ucs2(r.get_usmallint())
            self.conn.route = {
                "server": alt_server,
                "port": protocol_property,
            }
            # OLDVALUE = 0x00, 0x00
            r.get_usmallint()
        else:
            print("unknown env type: %d, skipping", type_id)
            # discard byte values, not still supported
            reader.skipall(size - 1)

        return packet