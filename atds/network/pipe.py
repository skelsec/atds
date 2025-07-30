import copy
import traceback
import asyncio

from atds.common.target import MSSQLTarget

from aiosmb.connection import SMBConnection
from aiosmb.commons.interfaces.file import SMBFile
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthProtocol
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer

class SMBPipeNetwork:
    def __init__(self, target:MSSQLTarget, credential:UniCredential):
        self.target = target
        self.credential = credential
        self.pipe = None
        self.connection = None
        self.packetizer = Packetizer()
        self.disconnect_event = asyncio.Event()
    
    def change_packetizer(self, packetizer):
        rem_data = self.packetizer.flush_buffer()
        if isinstance(self.packetizer, PacketizerSSL):
            self.packetizer.packetizer = packetizer
        else:
            self.packetizer = packetizer

    async def write(self, data:bytes):
        await self.pipe.write(data)
    
    async def read(self, size:int):
        return await self.pipe.read(size)
    
    async def close(self):
        self.disconnect_event.set()
        await self.pipe.close()
        await self.connection.disconnect()

    async def read_one(self):
        while not self.disconnect_event.is_set():
            data, err = await self.pipe.read(1024)
            if err is not None:
                raise err
            if len(data) > 0:
                async for packet in self.packetizer.data_in(data):
                    return packet
            else:
                break
    
    async def read(self):
        try:
            while not self.disconnect_event.is_set():
                data, err = await self.pipe.read(1024)
                if err is not None:
                    raise err
                if len(data) > 0:
                    async for packet in self.packetizer.data_in(data):
                        yield packet
                else:
                    break
        finally:
            #print('READ FINISHED')
            pass
            

    async def connect(self):
        try:
            if not isinstance(self.credential, UniCredential):
                gssapi = copy.deepcopy(self.credential)
            else:
                if self.credential.protocol == asyauthProtocol.KERBEROS:
                    kerberostarget = self.target.get_kerberos_target()
                    gssapi = SPNEGOCredential([self.credential]).build_context(target=kerberostarget)
                elif self.credential.protocol == asyauthProtocol.NTLM:
                    gssapi = SPNEGOCredential([self.credential]).build_context()
                else:
                    # straight up password with no indication of what protocol is used
                    # let's do ntlm that is more likely
                    smbntlmcred = copy.deepcopy(self.credential)
                    smbntlmcred.protocol = asyauthProtocol.NTLM
                    gssapi = SPNEGOCredential([smbntlmcred]).build_context()
                
            smbtarget = self.target.get_smb_target()
            self.connection = SMBConnection(gssapi, smbtarget)
            _, err = await self.connection.login()
            if err is not None:
                raise err
            
            self.pipe = SMBFile.from_smbtarget(smbtarget)
            _, err = await self.pipe.open_pipe(self.connection, 'rw')
            if err is not None:
                raise err
            return True, None
        except Exception as e:
            traceback.print_exc()
            return False, e
