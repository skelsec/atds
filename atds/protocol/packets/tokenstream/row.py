from io import BytesIO
from atds.tds.utils import BufferReader
from atds.protocol.packets.tokenstream.colmetadata import TDS_COLMETADATA

class TDS_ROW:
    TOKEN_TYPE = 0xD1  # ROW_TOKEN

    def __init__(self) -> None:
        self.length = None
        self.rows = []

    @staticmethod
    def from_bytes(data: bytes, column_metadata: TDS_COLMETADATA) -> 'TDS_ROW':
        """Reads and handles ROW stream.

        This stream contains list of values of one returned row.
        Stream format url: http://msdn.microsoft.com/en-us/library/dd357254.aspx
        """
        packet = TDS_ROW()
        r = BufferReader(BytesIO(data[1:]))
        column_metadata.info.row_count += 1
        for i, curcol in enumerate(column_metadata.info.columns):
            #curcol.value = curcol.serializer.read(r)
            packet.rows.append(curcol.serializer.read(r))
        packet.length = r.buffer.tell()
        return packet