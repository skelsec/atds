from io import BytesIO
from atds.tds.collate import ucs2_codec, Collation
import struct
from typing import Tuple, Any
from atds.tds import tds_base

class DummyLogin:
    def __init__(self):
        self.bytes_to_unicode = None

class DummyTDS:
    def __init__(self):
        self._login = DummyLogin()

class DummySession:
    def __init__(self):
        self.tzinfo_factory = None
        self._tds = DummyTDS()

class BufferReader:
    def __init__(self, buffer:BytesIO):
        self.buffer = buffer
        self.session = DummySession()
        self._session = self.session

    def check_size(self, size:int):
        if self.buffer.tell() + size > self.buffer.getbuffer().nbytes:
            raise tds_base.ClosedConnectionError()

    def get_usmallint(self):
        """Reads 16bit unsigned integer from the stream"""
        self.check_size(2)
        return int.from_bytes(self.buffer.read(2), byteorder='little', signed=False)

    def get_ushort(self) -> int:
        return self.get_usmallint()
    
    def get_byte(self) -> int:
        """Reads one byte from stream"""
        self.check_size(1)
        return self.buffer.read(1)[0]
    
    def get_smallint(self) -> int:
        """Reads 16bit signed integer from the stream"""    
        self.check_size(2)
        return int.from_bytes(self.buffer.read(2), byteorder='little', signed=True)
    
    
    def get_int(self) -> int:
        """Reads 32bit signed integer from the stream"""
        self.check_size(4)
        return int.from_bytes(self.buffer.read(4), byteorder='little', signed=True)

    def get_uint(self) -> int:
        """Reads 32bit unsigned integer from the stream"""
        self.check_size(4)
        return int.from_bytes(self.buffer.read(4), byteorder='little', signed=False)

    def get_uint_be(self) -> int:
        """Reads 32bit unsigned big-endian integer from the stream"""
        self.check_size(4)
        return int.from_bytes(self.buffer.read(4), byteorder='big', signed=False)

    def get_uint8(self) -> int:
        """Reads 64bit unsigned integer from the stream"""
        self.check_size(8)
        return int.from_bytes(self.buffer.read(8), byteorder='little', signed=False)

    def get_int8(self) -> int:
        """Reads 64bit signed integer from the stream"""
        self.check_size(8)
        return int.from_bytes(self.buffer.read(8), byteorder='little', signed=True)

    def read_ucs2(self, num_chars: int) -> str:
        """Reads num_chars UCS2 string from the stream"""
        self.check_size(num_chars * 2)
        buf = self.buffer.read(num_chars * 2)
        return ucs2_codec.decode(buf)[0]

    def read_str(self, size: int, codec) -> str:
        """Reads byte string from the stream and decodes it

        :param size: Size of string in bytes
        :param codec: Instance of codec to decode string
        :returns: Unicode string
        """
        self.check_size(size)
        data = self.buffer.read(size)
        return codec.decode(data)[0]

    def get_collation(self) -> Collation:
        """Reads :class:`Collation` object from stream"""
        self.check_size(Collation.wire_size)
        buf = self.buffer.read(Collation.wire_size)
        return Collation.unpack(buf)
    
    def unpack(self, struc: struct.Struct) -> Tuple[Any, ...]:
        """Unpacks given structure from stream

        :param struc: A struct.Struct instance
        :returns: Result of unpacking
        """
        self.check_size(struc.size)
        return struc.unpack(self.buffer.read(struc.size))


    def recv(self, size: int) -> bytes:
        """Reads exactly size bytes from stream

        :param size: Number of bytes to read
        :returns: Bytes read from stream
        """
        self.check_size(size)
        return self.buffer.read(size)

    def skipall(self, size: int):
        """Skips size bytes from stream"""
        self.check_size(size)
        self.buffer.read(size)
    
    def read(self, size: int) -> bytes:
        """Reads size bytes from stream"""
        self.check_size(size)
        return self.buffer.read(size)
