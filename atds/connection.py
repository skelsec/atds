import ssl
import asyncio
import random
import traceback
import copy
import re
import warnings
from datetime import datetime, date

from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.packetizers import Packetizer

from typing import cast, List, Tuple, Any, Union
from atds.common.target import MSSQLTarget
from atds.protocol.packets import TDSPacket, TDSStatus
from atds.network.packetizer import TDSPacketizer
from atds.protocol.packets import TDSPacketType
from atds.protocol.packets.prelogin import PreLoginOption, EncryptMode, TDS_PRELOGIN, PreLoginOptionToken
from atds.protocol.packets.login import TDS_LOGIN, TDS_LOGIN_FLAGS2
from atds.protocol.packets.tokenstream import TDSTokenType, TDSTokenParser
from atds.cursor import TDSCursor, QueryResult, RowType

from asyauth.common.constants import asyauthProtocol
from atds.network.pipe import SMBPipeNetwork

def encryptPassword(password:str | bytes) -> bytes:
    if isinstance(password, str):
        return bytes(bytearray([((x & 0x0f) << 4) + ((x & 0xf0) >> 4) ^ 0xa5 for x in password.encode('utf-16-le')]))
    else:
        return bytes(bytearray([((x & 0x0f) << 4) + ((x & 0xf0) >> 4) ^ 0xa5 for x in password]))


class MSSQLConnection:
    def __init__(self, target, credential, auth=None):
        self.target = target
        self.credential = credential
        self.auth = auth
        self.packetizer = TDSPacketizer()
        self._closed = False
        self.network = None
        self.handle_incoming_task = None

        # the SSL tunnel must be handled here
        self.tls_in_buff:ssl.MemoryBIO = None
        self.tls_out_buff:ssl.MemoryBIO = None
        self.tls_obj:ssl.SSLSocket = None

        # server prelogin info
        self.server_prelogin = None
        # this part will be moved to target
        self.packet_size = self.target.sqlpacketsize
        self.database = None


        # incoming data parser
        self.__token_parser = TDSTokenParser()
        self.__result_queue = asyncio.Queue()
        self.__query_lock = asyncio.Lock()

        self.connection_closed_event = asyncio.Event()
    
    def get_extra_info(self):
        try:
            ntlm_data = self.auth.get_extra_info()
        except:
            traceback.print_exc()
            ntlm_data = None
        return {'ntlm_data' : ntlm_data}
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc, traceback):
        await asyncio.wait_for(self.disconnect(), timeout = 1)

    async def __handle_incoming_ssl(self):
        # This is used after the prelogin and login have been sent and received
        # and encryption is enabled
        try:
            data_buffer = b''
            async for raw_data in self.network.read():
                if raw_data is None or len(raw_data) == 0:
                    break
                if len(raw_data) < 5:
                    continue

                data_buffer += raw_data
                while True:
                    if len(data_buffer) < 5:
                        break
                    record_length = int.from_bytes(data_buffer[3:5], byteorder='big')
                    total_record_length = record_length + 5  # header (5) + payload
                    if len(data_buffer) < total_record_length:
                        break
                    self.tls_in_buff.write(data_buffer[:total_record_length])
                    data_buffer = data_buffer[total_record_length:]
                    decrypted_data = b''
                    while True:
                        try:
                            tempdata = self.tls_obj.read()
                        except ssl.SSLWantReadError:
                            break
                        if tempdata is None or len(tempdata) == 0:
                            break
                        decrypted_data += tempdata
                    await self.__handle_incoming_packet_data(decrypted_data)


        except Exception as e:
            traceback.print_exc()
        finally:
            await self.disconnect()

    async def __handle_incoming(self):
        # This is used before the prelogin and login have been sent and received
        # and encryption is disabled
        try:
            async for raw_data in self.network.read():
                if raw_data is None or len(raw_data) == 0:
                    break
                
                await self.__handle_incoming_packet_data(raw_data)
                    
        except Exception as e:
            traceback.print_exc()
        finally:
            print('INCOMING READ FINISHED')
            await self.disconnect()

    async def __handle_incoming_packet_data(self, raw_data):
        try:
            async for packet in self.packetizer.data_in(raw_data):
                if packet is None:
                    break
                if packet.Type == TDSPacketType.TABULAR_RESULT:
                    for tokentype, token in self.__token_parser.from_bytes(packet.Data):
                        await self.__result_queue.put((packet.Type, tokentype, token))
                
                else:
                    await self.__result_queue.put((packet.Type, None, packet))
                if TDSStatus.EOM in packet.Status:
                    break
        except Exception as e:
            raise e


    async def __login_send_recv(self, packet:TDSPacket) -> TDSPacket:
        # This is used to send and receive a TDS packet during the login process
        # Do not use this for other purposes
        if self.tls_obj is None:
            # No TLS - send and receive raw TDS packets
            await self.network.write(packet.to_bytes())
            return await self.network.read_one()
        
        # With TLS - encrypt TDS packet, send, receive encrypted response, decrypt
        self.tls_obj.write(packet.to_bytes())
        while True:
            raw = self.tls_out_buff.read()
            if raw != b'':
                await self.network.write(raw)
                continue
            break
        
        if self.server_encryption == EncryptMode.ENCRYPT_OFF:
            self.tls_obj = None
            self.network.change_packetizer(TDSPacketizer())
            return await self.network.read_one()

        # Read TLS records one at a time
        response_data = b''
        while True:
            # Read TLS record header (5 bytes) to determine record length
            chunk = await self.network.read_one()
            if chunk is None or len(chunk) == 0:
                break
                
            # TLS record header format:
            # Byte 0: Content Type
            # Bytes 1-2: Protocol Version
            # Bytes 3-4: Length (big-endian)
            record_length = int.from_bytes(chunk[3:5], byteorder='big')
            total_record_length = record_length + 5  # header (5) + payload
            
            # If we received more data than needed, only process up to record boundary
            if len(chunk) > total_record_length:
                response_data += chunk[:total_record_length]
                break
            elif len(chunk) == total_record_length:
                response_data += chunk
                break
            else:
                # Need to read more data to complete this record
                response_data += chunk
                remaining = total_record_length - len(chunk)
                while remaining > 0:
                    chunk = await self.network.read_one()
                    if chunk is None or len(chunk) == 0:
                        break
                    response_data += chunk
                    remaining = total_record_length - len(response_data)
                break
        
        # Decrypt the response and create a new TDS packet
        self.tls_in_buff.write(response_data)
        decrypted_data = b''
        while True:
            try:
                tempdata = self.tls_obj.read()
            except ssl.SSLWantReadError:
                break
            if tempdata is not None and len(tempdata) > 0:
                decrypted_data += tempdata
                break
        response_packet = TDSPacket.from_bytes(decrypted_data)
        return response_packet
    
    
    
    async def disconnect(self):
        try:
            if self._closed is True:
                return
            self._closed = True
            
            if self.network is not None:
                await self.network.close()
            if self.handle_incoming_task is not None:
                self.handle_incoming_task.cancel()
            self.__handle_incoming_packet_data.put_nowait(None)
        finally:
            self.connection_closed_event.set()
    
    async def fake_login(self):
        try:
            client = UniClient(self.target, self.packetizer)
            self.network = await asyncio.wait_for(client.connect(), timeout=self.target.timeout)
            await self.prelogin()
            return True, None
        except Exception as e:
            return False, e
    
    async def connect(self) -> tuple[bool, Exception]:
        try:
            if self.target.pipename is None:
                self.packetizer = TDSPacketizer()
                client = UniClient(self.target, self.packetizer)
                self.network = await asyncio.wait_for(client.connect(), timeout=self.target.timeout)
            else:
                self.network = SMBPipeNetwork(self.target, self.credential)
                _, err = await self.network.connect()
                if err is not None:
                    raise err
                self.network.change_packetizer(self.packetizer)
            await self.prelogin()
            await self.login()

            self.network.change_packetizer(Packetizer())
            if self.tls_obj is not None:
                self.handle_incoming_task = asyncio.create_task(self.__handle_incoming_ssl())
            else:
                self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
            return True, None
        except Exception as e:
            return False, e
    
    async def login(self):
        login = TDS_LOGIN()
        login.app_name = self.target.sqlappname
        login.client_name = self.target.sqlclientname
        login.server_name = self.target.get_hostname_or_ip()
        login.client_pid = self.target.sqlpid
        login.packet_size = self.packet_size
        login.library_name = login.app_name
        if self.target.database is not None:
            login.database = self.target.database
        login.flags2 = TDS_LOGIN_FLAGS2.SET_LANG_ON | TDS_LOGIN_FLAGS2.INIT_DB_FATAL
        
        if self.credential.protocol == asyauthProtocol.PLAIN:
            login.username = self.credential.username
            login.password = encryptPassword(self.credential.secret)
            login_data = login.to_bytes()
            packet = TDSPacket()
            packet.Type = TDSPacketType.TDS7_LOGIN
            packet.Data = login_data
            packet.PacketID = 1
            response_packet = await self.__login_send_recv(packet)
            rtype, rtokentype, response = response_packet.parse_data()
            if rtype == TDSPacketType.TABULAR_RESULT:
                if rtokentype == TDSTokenType.DONE:
                    return
                elif rtokentype == TDSTokenType.ERROR:
                    raise Exception(response.message)
            else:
                raise Exception(f"Unexpected packet type: {rtype}")
        
        elif self.credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS]:
           
            if self.credential.protocol == asyauthProtocol.KERBEROS:
                # This is using SPNEGO
                from asyauth.common.credentials.spnego import SPNEGOCredential
                
                kerberostarget = self.target.get_kerberos_target()
                self.auth = SPNEGOCredential([self.credential]).build_context(target=kerberostarget)
            else:
                 # This is using raw NTLM, not SPNEGO
                self.auth = self.credential.build_context()
            login.flags2 |= TDS_LOGIN_FLAGS2.INTEGRATED_SECURITY

            token = None
            while True:
                data, to_continue, err = await self.auth.authenticate(token, flags = None, spn=self.target.to_target_string())
                if err is not None:
                    raise err
                if to_continue is False and data is None or data == b'':
                    break

                login.sspi = data

                if token is None:
                    login_data = login.to_bytes()
                    packet = TDSPacket()
                    packet.Type = TDSPacketType.TDS7_LOGIN
                    packet.Data = login_data
                    packet.PacketID = 1
                else:
                    packet = TDSPacket()
                    packet.Type = TDSPacketType.TABULAR_RESULT
                    packet.Data = data
                    packet.PacketID = 1
                response_packet = await self.__login_send_recv(packet)
                rtype, rtokentype, response = response_packet.parse_data()
                if rtype == TDSPacketType.TABULAR_RESULT:
                    if rtokentype == TDSTokenType.DONE:
                        # login OK for NTLM
                        break
                    if rtokentype == TDSTokenType.LOGINACK:
                        # login OK for SSPI/Kerberos
                        break

                    elif rtokentype == TDSTokenType.ERROR:
                        raise Exception(response.message)
                    elif rtokentype == TDSTokenType.SSPI:
                        token = response.sspi_buffer
                else:
                    raise Exception(f"Unexpected packet type: {rtype}")
                
                if to_continue is False:
                    break
        else:
            raise Exception(f"Unsupported protocol: {self.credential.protocol} Only NTLM and Kerberos and PLAIN are supported")
        
        

    async def prelogin(self):
        version_opt = PreLoginOption.create_version(
            major=self.target.sqlvermajor,
            minor=self.target.sqlverminor,
            build=self.target.sqlverbuild
        )
        encryption_opt = PreLoginOption.create_encryption(EncryptMode.ENCRYPT_ON if self.target.sqlencrypt else EncryptMode.ENCRYPT_OFF)
        instance_opt = PreLoginOption.create_instance(self.target.sqlinstance)
        threadid_opt = PreLoginOption.create_threadid(self.target.sqlthreadid)
        prelogin_options = [version_opt, encryption_opt, instance_opt, threadid_opt]
        
        prelogin = TDS_PRELOGIN()
        prelogin.options = prelogin_options
        packet_data = prelogin.to_bytes()

        packet = TDSPacket()
        packet.Type = TDSPacketType.PRELOGIN
        packet.Data = packet_data
        await self.network.write(packet.to_bytes())

        response_packet = await self.network.read_one()
        self.server_prelogin = TDS_PRELOGIN.from_bytes(response_packet.Data)

        self.server_encryption = EncryptMode.ENCRYPT_OFF
        if self.server_prelogin.get_option(PreLoginOptionToken.ENCRYPTION) is not None:
            encopt = self.server_prelogin.get_option(PreLoginOptionToken.ENCRYPTION)
            if encopt is not None:
                self.server_encryption = encopt.get_encryption()

        # check if encryption is required
        
        if self.server_encryption in [EncryptMode.ENCRYPT_OFF, EncryptMode.ENCRYPT_REQ, EncryptMode.ENCRYPT_ON]:
            # this is wierd, but this means we need to use SSL
            self.ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_ctx.set_ciphers('ALL:@SECLEVEL=0')
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

            self.tls_in_buff = ssl.MemoryBIO()
            self.tls_out_buff = ssl.MemoryBIO()
            self.tls_obj = self.ssl_ctx.wrap_bio(self.tls_in_buff, self.tls_out_buff, server_side=False)
            while True:
                try:
                    self.tls_obj.do_handshake()
                except ssl.SSLWantReadError:
                    client_hello = self.tls_out_buff.read()
                    # wrap it in a TDS_PRELOGIN packet
                    packet = TDSPacket()
                    packet.Type = TDSPacketType.PRELOGIN
                    packet.Data = client_hello
                    await self.network.write(packet.to_bytes())
                    response_packet = await self.network.read_one()
                    self.tls_in_buff.write(response_packet.Data)
                    continue
                else:
                    server_fin = self.tls_out_buff.read()
                    if server_fin != b'':
                        packet = TDSPacket()
                        packet.Type = TDSPacketType.PRELOGIN
                        packet.Data = server_fin
                        await self.network.write(packet.to_bytes())
                    break
            self.network.change_packetizer(Packetizer()) # change to the default packetizer
            self.packet_size = 16*1024-1
        
    
    async def send_packet(self, packet:TDSPacket):
        # This is used to send a TDS packet to the server after the prelogin and login have been sent and received
        # Will automatically encrypt the packet if encryption is enabled
        if self.tls_obj is None:
            await self.network.write(packet.to_bytes())
        else: 
            self.tls_obj.write(packet.to_bytes())
            while True:
                raw = self.tls_out_buff.read()
                if raw != b'':
                    await self.network.write(raw)
                    continue
                break


    def get_cursor(self, stream:bool = False, rowtype:Union[str, RowType] = RowType.LIST):
        # TODO: this function will need to be updated to support MARS and other features
        return TDSCursor(self, stream, rowtype)

    async def batch_raw(self, sql:str):
        try:
            async with self.__query_lock:
                packet = TDSPacket()
                packet.Type = TDSPacketType.SQL_BATCH
                packet.Data = sql.encode('utf-16-le')
                await self.send_packet(packet)
                while True:
                    packettype, tokentype, token = await self.__result_queue.get()
                    #print(f"packettype: {packettype}, tokentype: {tokentype.name}")
                    if token is None:
                        break
                    
                    yield packettype, tokentype, token
                    
                    if tokentype in [TDSTokenType.DONE, TDSTokenType.DONEINPROC, TDSTokenType.DONEPROC]:
                        if token.is_final is True:
                            break
                    
        except Exception as e:
            traceback.print_exc()

    async def batch(self, sql:str):
        result = QueryResult()
        async for packettype, tokentype, token in self.batch_raw(sql):
            if packettype == TDSPacketType.TABULAR_RESULT:
                if tokentype == TDSTokenType.ERROR:
                    result.add_error(token)
                elif tokentype == TDSTokenType.ROW:
                    result.add_row(token.values)
                elif tokentype == TDSTokenType.COLMETADATA:
                    result.add_colmetadata(token)
                elif tokentype in [TDSTokenType.DONE, TDSTokenType.DONEINPROC, TDSTokenType.DONEPROC]:
                    result.add_done(token)
                elif tokentype == TDSTokenType.ORDER:
                    result.add_order(token)
                else:
                    print(f"Unknown token type: {tokentype.name}")
            else:
                print(f"Unknown packet type: {packettype}")
        return result

if __name__ == "__main__":
    from asysocks.unicomm.common.target import UniTarget, UniProto
    from asyauth.common.credentials import UniCredential
    from asyauth.common.constants import  asyauthProtocol, asyauthSecret


    target = MSSQLTarget("braavos.essos.local", port = 1433, protocol = UniProto.CLIENT_TCP, dc_ip="192.168.56.12")
    credential = UniCredential(
        secret="iknownothing",
        username="jon.snow",
        domain="north.sevenkingdoms.local",
        stype=asyauthSecret.PASSWORD,
        protocol=asyauthProtocol.KERBEROS,
    )

    #credential = UniCredential(
    #    secret="195e021e4c0ae619f612fb16c5706bb6",
    #    username="drogon",
    #    domain="essos.local",
    #    stype=asyauthSecret.NT,
    #    protocol=asyauthProtocol.KERBEROS,
    #)
    
    async def main():
        connection = MSSQLConnection(target, credential)
        await connection.connect()
        result = await connection.batch("use master")
        print(result)

        input('1')
        result = await connection.batch("select @@version")
        print(result)
        input('2')
        query = """
SELECT TOP 10 
        name AS LoginName,
        create_date AS CreationDate,
        modify_date AS LastModified,
        type_desc AS LoginType
    FROM sys.server_principals
    WHERE type NOT IN ('C', 'K')  -- Exclude certificates and keys
    ORDER BY create_date DESC;
        """
        result = await connection.batch(query)
        print(result)
        input('3')
        query = """
WITH Numbers AS (
    SELECT TOP 1000 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n
    FROM sys.objects a
    CROSS JOIN sys.objects b
)
SELECT 
    n.n AS RowNum,
    REPLICATE(CONVERT(varchar(max), s1.name), 10) AS RepeatedName1,
    REPLICATE(CONVERT(varchar(max), s2.name), 10) AS RepeatedName2,
    REPLICATE(CONVERT(varchar(max), s1.type_desc), 5) AS RepeatedType1,
    REPLICATE(CONVERT(varchar(max), s2.type_desc), 5) AS RepeatedType2,
    s1.create_date,
    s2.modify_date,
    REPLICATE(CONVERT(varchar(max), OBJECT_DEFINITION(s1.object_id)), 2) AS ObjectDef1,
    REPLICATE(CONVERT(varchar(max), OBJECT_DEFINITION(s2.object_id)), 2) AS ObjectDef2
FROM Numbers n
CROSS JOIN sys.objects s1
CROSS JOIN sys.objects s2
WHERE s1.type_desc NOT IN ('AGGREGATE_FUNCTION', 'DEFAULT_CONSTRAINT')
    AND s2.type_desc NOT IN ('AGGREGATE_FUNCTION', 'DEFAULT_CONSTRAINT')
ORDER BY n.n, s1.name, s2.name;
        """
        result = await connection.batch(query)
        print(result)
        input('4')
    asyncio.run(main())