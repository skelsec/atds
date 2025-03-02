from dataclasses import dataclass, field
from enum import IntFlag, IntEnum
from typing import Optional, Dict, Any
import copy
import os

class TDS_LOGIN_FLAGS(IntFlag):
    BYTEORDER = 0x00            # USE_DB_ON
    CHAR = 0x01                 # Char = 1, Wchar = 0
    FLOAT = 0x02               # Float = 1, Float4 = 0
    DUMPLOAD = 0x04            # Dump/Load = 1, Normal = 0
    USE_DB = 0x08              # Use DB = 1, Don't use = 0
    DATABASE = 0x10            # Init Database = 1, Don't init = 0
    SET_LANG = 0x20            # Set LANGUAGE = 1, Don't set = 0
    LANGUAGE = 0x40            # Initial language = 1, Don't set = 0
    ODBC = 0x80               # ODBC = 1, Not ODBC = 0
    SSPI_REQ = 0x100          # SSPI requested = 1, Not requested = 0

class TDS_LOGIN_FLAGS2(IntFlag):
    INIT_DB_FATAL = 0x01       # Initial DB failure fatal = 1
    SET_LANG_ON = 0x02         # SET LANGUAGE enabled = 1
    INTEGRATED_SECURITY = 0x80  # Integrated Security = 1

class TDS_LOGIN_FLAGS3(IntFlag):
    CHANGE_PASSWORD = 0x01      # Change Password = 1
    SEND_YUKON_BINARY = 0x02    # Send Yukon binary XML = 1
    USER_INSTANCE = 0x04        # User Instance = 1
    UNKNOWN_COLLATION = 0x08    # Unknown Collation Handling = 1
    EXTENSION = 0x10           # Extension = 1

class TDS_TYPE_FLAGS(IntFlag):
    SQL_DFLT = 0x00            # SQL_DFLT
    SQL_TSQL = 0x01            # SQL_TSQL
    OLEDB = 0x02               # OLEDB
    READ_ONLY_INTENT = 0x04    # Read-Only Intent

@dataclass
class OffsetLength:
    offset: int
    length: int

@dataclass
class TDSLoginField:
    """Represents a variable-length field in the TDS login packet"""
    value: str = ""
    offset: int = 0
    length: int = 0

@dataclass
class TDSLoginFieldBytes:
    value: bytes = b''
    offset: int = 0
    length: int = 0

@dataclass
class TDSLoginFieldClientID:
    value: bytes = b'\x11\x22\x33\x44\x55\x66' #os.urandom(6) #6 random bytes

class TDS_LOGIN:
    def __init__(self):
        # Fixed length fields
        self.length: int = 0
        self.tds_version: int = 0x71000000 #0x74000004  # SQL Server 2012-2019
        self.packet_size: int = 4096
        self.client_prog_ver: int = 0
        self.client_pid: int = 0
        self.client_id: int = 0
        self.flags1: int = 0
        self.flags2: int = 0
        self.type_flags: int = 0
        self.flags3: int = 0
        self.client_timezone: int = 0
        self.client_lcid: int = 0
        
        # Variable length fields stored as TDSLoginField objects
        self.fields: Dict[str, TDSLoginField] = {
            'hostname': TDSLoginField(),
            'username': TDSLoginField(),
            'password': TDSLoginFieldBytes(),
            'app_name': TDSLoginField(),
            'server_name': TDSLoginField(),
            'unused': TDSLoginFieldBytes(),
            'library_name': TDSLoginField(),
            'language': TDSLoginField(),
            'database': TDSLoginField(),
            'clientid': TDSLoginFieldClientID(), # this is super weird
            'sspi': TDSLoginFieldBytes(),
            'attachdbfilename': TDSLoginField(),
        }

    def __setattr__(self, name: str, value: Any) -> None:
        """Override setattr to handle string fields specially"""
        # Access fields directly from __dict__ to avoid recursion
        fields = self.__dict__.get('fields', {})
        if name in fields:
            if isinstance(fields[name], TDSLoginFieldBytes):
                if isinstance(value, str):
                    raise ValueError("String value not allowed for TDSLoginFieldBytes")
                fields[name].value = value
                fields[name].length = len(value)
            else:
                fields[name].value = value
                fields[name].length = len(value)
        else:
            super().__setattr__(name, value)

    def __getattr__(self, name: str) -> Any:
        """Override getattr to handle string fields specially"""
        # Access fields directly from __dict__ to avoid recursion
        fields = self.__dict__.get('fields', {})
        if name in fields:
            return fields[name].value
        raise AttributeError(f"'TDS_LOGIN' object has no attribute '{name}'")

    def to_bytes(self) -> bytes:
        # Calculate offsets first
        current_offset = 9*4 + len(self.fields)*4 + 6 # 6 is the length of the clientid field
        current_offset = 86

        # First pass: set all offsets
        fields_serialized = []

        for fieldname in self.fields:
            field = self.fields[fieldname]
            if isinstance(field, TDSLoginField):
                if field.value == "":
                    if fieldname != 'hostname':
                        fields_serialized.append(TDSLoginField(value=b"", length=0, offset=current_offset))
                    else:
                        fields_serialized.append(TDSLoginField(value="EMPTY".encode('utf-16-le'), length=5, offset=current_offset))
                        current_offset += 10
                    continue
                newfiled = copy.deepcopy(field)
                newvalue = newfiled.value.encode('utf-16-le')
                newfiled.value = newvalue
                newfiled.offset = current_offset
                current_offset += len(newvalue)
                fields_serialized.append(newfiled)
            elif isinstance(field, TDSLoginFieldClientID):
                fields_serialized.append(field)
                # not modifying the offset here, because it's a random 6 bytes
                #current_offset += len(field.value)
                continue
            else:
                #if len(field.value) == 0:
                #    continue
                newfiled = copy.deepcopy(field)
                newfiled.offset = current_offset
                if fieldname == 'password':
                    newfiled.length = len(newfiled.value)//2
                current_offset += len(newfiled.value)
                fields_serialized.append(newfiled)
            
        
        # Build the packet
        packet = bytearray()
        
        # Add packet length (will be updated at the end)
        packet.extend(int(0).to_bytes(4, byteorder='little'))
        
        # Add fixed length fields
        packet.extend(self.tds_version.to_bytes(4, byteorder='little'))
        packet.extend(self.packet_size.to_bytes(4, byteorder='little'))
        packet.extend(self.client_prog_ver.to_bytes(4, byteorder='little'))
        packet.extend(self.client_pid.to_bytes(4, byteorder='little'))
        packet.extend(self.client_id.to_bytes(4, byteorder='little'))
        packet.extend(self.flags1.to_bytes(1, byteorder='little'))
        packet.extend(self.flags2.to_bytes(1, byteorder='little'))
        packet.extend(self.type_flags.to_bytes(1, byteorder='little'))
        packet.extend(self.flags3.to_bytes(1, byteorder='little'))
        packet.extend(self.client_timezone.to_bytes(4, byteorder='little'))
        packet.extend(self.client_lcid.to_bytes(4, byteorder='little'))
        
        # Add offset/length pairs for all fields
        for field in fields_serialized:
            if isinstance(field, TDSLoginFieldClientID):
                packet.extend(field.value)
                continue
            packet.extend(field.offset.to_bytes(2, byteorder='little'))
            packet.extend(field.length.to_bytes(2, byteorder='little'))
        
        # Add the variable length data
        for field in fields_serialized:
            if isinstance(field, TDSLoginFieldClientID):
                continue
            if field.length > 0:
                packet.extend(field.value)

        # Update packet length
        packet[0:4] = len(packet).to_bytes(4, byteorder='little')
        
        return bytes(packet)
    @classmethod
    def from_bytes(cls, data: bytes) -> 'TDS_LOGIN':
        login = cls()
        
        # Parse fixed length header
        login.length = int.from_bytes(data[0:4], byteorder='little')
        login.tds_version = int.from_bytes(data[4:8], byteorder='little')
        login.packet_size = int.from_bytes(data[8:12], byteorder='little')
        login.client_prog_ver = int.from_bytes(data[12:16], byteorder='little')
        login.client_pid = int.from_bytes(data[16:20], byteorder='little')
        login.client_id = int.from_bytes(data[20:24], byteorder='little')
        login.flags1 = data[24]
        login.flags2 = data[25]
        login.type_flags = data[26]
        login.flags3 = data[27]
        login.client_timezone = int.from_bytes(data[28:32], byteorder='little')
        login.client_lcid = int.from_bytes(data[32:36], byteorder='little')
        
        # Parse offset/length pairs and data
        offset = 36
        for field_name in login.fields:
            field = login.fields[field_name]
            field.offset = int.from_bytes(data[offset:offset+2], byteorder='little')
            field.length = int.from_bytes(data[offset+2:offset+4], byteorder='little')
            
            if field.length > 0:
                if isinstance(field, TDSLoginFieldBytes):
                    field.value = data[field.offset:field.offset+field.length]
                else:
                    field.value = data[field.offset:field.offset+field.length].decode('utf-16-le')
            
            offset += 4
            
        return login
    
    def __str__(self):
        fixed_fields = [
            f"Length: {self.length}",
            f"TDS Version: 0x{self.tds_version:08x}",
            f"Packet Size: {self.packet_size}",
            f"Client Program Version: 0x{self.client_prog_ver:08x}",
            f"Client PID: {self.client_pid}",
            f"Client ID: {self.client_id}",
            f"Flags1: 0x{self.flags1:02x} ({TDS_LOGIN_FLAGS(self.flags1)})",
            f"Flags2: 0x{self.flags2:02x} ({TDS_LOGIN_FLAGS2(self.flags2)})",
            f"Type Flags: 0x{self.type_flags:02x} ({TDS_TYPE_FLAGS(self.type_flags)})",
            f"Flags3: 0x{self.flags3:02x} ({TDS_LOGIN_FLAGS3(self.flags3)})",
            f"Client Timezone: {self.client_timezone}",
            f"Client LCID: {self.client_lcid}"
        ]

        variable_fields = []
        for name, field in self.fields.items():
            if isinstance(field, TDSLoginFieldBytes):
                value = field.value.hex()
            elif isinstance(field, TDSLoginFieldClientID):
                value = field.value.hex()
                field.offset = 0
                field.length = 0
            else:
                value = field.value
            variable_fields.append(f"{name}: '{value}' (offset: {field.offset}, length: {field.length})")

        return "TDS_LOGIN {\n    " + \
               "\n    ".join(fixed_fields) + \
               "\n\n    " + \
               "\n    ".join(variable_fields) + \
               "\n}"

