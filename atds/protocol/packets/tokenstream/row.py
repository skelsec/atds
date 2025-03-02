import io
from atds.tds.utils import BufferReader
from atds.protocol.packets.tokenstream.colmetadata import TDS_COLMETADATA
from atds.protocol.packets.tokenstream import TDSTokenStreamBase
class TDS_ROW(TDSTokenStreamBase):
    TOKEN_TYPE = 0xD1  # ROW_TOKEN

    def __init__(self, **kwargs) -> None:
        super().__init__(0xD1, **kwargs)
        self.values = []

    def from_reader(self, reader: BufferReader) -> 'TDS_ROW':
        """Reads and handles ROW stream.        

        This stream contains list of values of one returned row.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd357254.aspx
        """
        # Verify token type
        token = reader.get_byte()
        if token != TDS_ROW.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xD1, got {hex(token)}")
        self.column_metadata.info.row_count += 1
        for i, curcol in enumerate(self.column_metadata.info.columns):
            #curcol.value = curcol.serializer.read(r)
            self.values.append(curcol.serializer.read(reader))
        return self