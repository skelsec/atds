from atds.tds.utils import BufferReader
from atds.protocol.packets.tokenstream.colmetadata import TDS_COLMETADATA
from atds.tds import tds_base
import io
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class TDS_RETURNVALUE(TDSTokenStreamBase):
    TOKEN_TYPE = 0xAC  # RETURNVALUE_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xAC, **kwargs)
        self.param: tds_base.Column = None
        self.ordinal: int = 0
        self.column_name: str = ""

    def from_reader(self, reader: BufferReader) -> 'TDS_RETURNVALUE':
        # Verify token type
        token = reader.get_byte()
        if token != TDS_RETURNVALUE.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xAC, got {hex(token)}")
        if tds_base.IS_TDS72_PLUS(self.tds_version):
            self.ordinal = reader.get_usmallint()
        else:
            reader.get_usmallint()  # ignore size
            self.ordinal = reader.get_usmallint()

        name = reader.read_ucs2(reader.get_byte())
        reader.get_byte()  # 1 - OUTPUT of sp, 2 - result of udf
        param = tds_base.Column()
        param.column_name = name
        self.column_name = name
        TDS_COLMETADATA.get_type_info(self.tds_version, param, reader)
        param.value = param.serializer.read(reader)
        self.param = param
        return self
