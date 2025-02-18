from dataclasses import dataclass
from enum import IntFlag
from typing import List, Optional
from io import BytesIO
from atds.tds.column import Column
from atds.tds.types import SerializerFactory
from atds.tds.tds_base import IS_TDS72_PLUS, TDS71, TDS74, _Results
from atds.tds.collate import ucs2_codec, Collation
from typing import Callable, Iterable, Any, Tuple
from atds.tds.utils import BufferReader


def tuple_row_strategy(
    column_names: Iterable[str]
) -> Callable[[Iterable[Any]], Tuple[Any, ...]]:
    """Tuple row strategy, rows returned as tuples, default"""
    return tuple


class ColumnFlags(IntFlag):
    """Column flags in least significant bit order (LSB first)"""
    NULLABLE = 0x01              # Bit 0: Column is nullable
    CASE_SENSITIVE = 0x02        # Bit 1: Column is case-sensitive
    UPDATEABLE_READONLY = 0x00   # Bits 2-3: Column is read-only
    UPDATEABLE_READWRITE = 0x04  # Bits 2-3: Column is read/write
    UPDATEABLE_UNKNOWN = 0x08    # Bits 2-3: Updateable is unknown
    IDENTITY = 0x10              # Bit 4: Column is identity
    COMPUTED = 0x20              # Bit 5: Column is computed (TDS 7.2+)
    FIXED_LEN_CLR_TYPE = 0x100   # Bit 8: Column is fixed-length CLR UDT (TDS 7.2+)
    SPARSE_COLUMN_SET = 0x200    # Bit 9: Column is sparse column set (TDS 7.3.B+)
    ENCRYPTED = 0x400            # Bit 10: Column is encrypted (TDS 7.4+)
    NULLABLE_UNKNOWN = 0x1000    # Bit 12: Nullable unknown (TDS 7.2+)
    HIDDEN = 0x4000             # Bit 14: Column is hidden
    KEY = 0x8000                # Bit 15: Column is key

@dataclass
class TableName:
    """Fully qualified base table name for text/ntext/image columns"""
    num_parts: int
    parts: List[str]

@dataclass
class CryptoMetaData:
    """Encryption metadata for a column (TDS 7.4+)"""
    ordinal: int
    user_type: int
    base_type_info: bytes  # TYPE_INFO for plaintext
    encryption_algo: int
    algo_name: Optional[str]
    encryption_algo_type: int
    norm_version: int

@dataclass
class ColumnData:
    """Metadata for a single column"""
    user_type: int
    flags: ColumnFlags
    type_info: bytes            # TYPE_INFO structure
    table_name: Optional[TableName] = None
    crypto_metadata: Optional[CryptoMetaData] = None
    column_name: str = ""

class TDS_COLMETADATA:
    TOKEN_TYPE = 0x81  # COLMETADATA_TOKEN

    def __init__(self) -> None:
        self.count: int = 0
        self.columns: List[ColumnData] = []
        self.cek_table: List[bytes] = []  # Encryption keys table (TDS 7.4+)
        self.length: int = 0
        self.row_strategy = None
        self.info = None

    @staticmethod
    def from_bytes(data: bytes, tds_version: int = TDS71) -> 'TDS_COLMETADATA':
        
        if len(data) < 3:  # Minimum: token(1) + count(2)
            raise ValueError("COLMETADATA data too short")

        stream = BytesIO(data)
        
        # Verify token type
        token = stream.read(1)[0]
        if token != TDS_COLMETADATA.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0x81, got {hex(token)}")

        packet = TDS_COLMETADATA()

        # Parse column count (2 bytes)
        packet.count = int.from_bytes(stream.read(2), byteorder='little')

        # Check for NoMetaData case
        if packet.count == 0xFFFF:
            return packet

        # Parse CEK table if encryption is enabled (TDS 7.4+)
        if tds_version >= TDS74:
            ek_count = int.from_bytes(stream.read(2), byteorder='little')
            for _ in range(ek_count):
                # Parse EK_INFO structure
                ek_length = int.from_bytes(stream.read(2), byteorder='little')
                packet.cek_table.append(stream.read(ek_length))

        info = _Results()
        columns = []
        header_tuple = []
        # Parse each column's metadata
        r = BufferReader(stream)
        for _ in range(packet.count):
            curcol = Column()
            columns.append(curcol)
            info.columns.append(curcol)
            TDS_COLMETADATA.get_type_info(tds_version, curcol, r)
            curcol.column_name = r.read_ucs2(r.get_byte())

            precision = curcol.serializer.precision
            scale = curcol.serializer.scale
            size = curcol.serializer.size
            header_tuple.append(
                (
                    curcol.column_name,
                    curcol.serializer.get_typeid(),
                    None,
                    size,
                    precision,
                    scale,
                    curcol.flags & Column.fNullable,
                )
            )
        
        info.description = tuple(header_tuple)
        packet.columns = columns
        packet.header_tuple = header_tuple
        packet.length = stream.tell() - 3

        column_names = [col[0] for col in info.description]
        packet.row_strategy = tuple_row_strategy(column_names)
        packet.info = info
        return packet
            
    def __str__(self):
        return f"TDS_COLMETADATA(count={self.count}, columns={self.columns})"

    @staticmethod
    def get_type_info(tds_version, curcol, reader:'BufferReader'):
        
            """Reads TYPE_INFO structure (http://msdn.microsoft.com/en-us/library/dd358284.aspx)

            :param curcol: An instance of :class:`Column` that will receive read information
            """
            type_factory = SerializerFactory(tds_version)
            # User defined data type of the column
            if IS_TDS72_PLUS(tds_version):
                user_type = reader.get_uint()
            else:
                user_type = reader.get_usmallint()
            curcol.column_usertype = user_type
            curcol.flags = reader.get_usmallint()
            type_id = reader.get_byte()
            serializer_class = type_factory.get_type_serializer(type_id)
            curcol.serializer = serializer_class.from_stream(reader)

