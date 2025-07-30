from atds.common.target import MSSQLTarget
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol
from atds.connection import MSSQLConnection
import copy

class MSSQLConnectionFactory:
    def __init__(self, target: MSSQLTarget, credential: UniCredential, smbcredential: UniCredential = None):
        self.target = target
        self.credential = credential
        self.smbcredential = smbcredential # used for pipe connections, if not provided, will use the self.credential for both SMB and MSSQL

    def get_connection(self) -> MSSQLConnection:
        return MSSQLConnection(
            self.get_target(),
            self.get_credential(),
            smbcredential = self.get_smbcredential()
        )
    
    def get_credential(self) -> UniCredential:
        return copy.deepcopy(self.credential)
    
    def get_smbcredential(self) -> UniCredential:
        return copy.deepcopy(self.smbcredential)
    
    def get_target(self) -> MSSQLTarget:
        return copy.deepcopy(self.target)

    def create_connection_newtarget(self, ip_or_hostname: str, database: str = None, encrypt: bool = True) -> MSSQLConnection:
        target = MSSQLTarget(
            ip = ip_or_hostname,
            port = self.target.port,
            database = database,
            sqlencrypt = encrypt,
            proxies = copy.deepcopy(self.target.proxies) if self.target.proxies is not None else None,
            dc_ip = self.target.dc_ip,
            domain = self.target.domain,
            dns=self.target.dns
        )
        return MSSQLConnection(target, self.get_credential(), smbcredential = self.get_smbcredential())
    
    @staticmethod
    def from_connection(connection: MSSQLConnection) -> 'MSSQLConnectionFactory':
        return MSSQLConnectionFactory(
            copy.deepcopy(connection.target),
            copy.deepcopy(connection.credential),
            smbcredential = copy.deepcopy(connection.smbcredential)
        )
    
    def __str__(self) -> str:
        return f"MSSQLConnectionFactory(target={self.target}, credential={self.credential}, smbcredential={self.smbcredential})"
    
    def __repr__(self) -> str:
        return self.__str__()
    
    @staticmethod
    def from_url(url: str, smbcredential: UniCredential = None) -> 'MSSQLConnectionFactory':
        target = MSSQLTarget.from_url(url)
        credential = UniCredential.from_url(url)
        # TODO: we will need to add a separate credential for SMB, but for now, we will use the same credential for both SMB and MSSQL
        return MSSQLConnectionFactory(target, credential, smbcredential = smbcredential)
    
    @staticmethod
    def from_params(hostname:str, database:str, username:str, password:str, domain:str = None, port:int = 1433, authprotocol:str = 'plain') -> 'MSSQLConnectionFactory':
        authprotocol = authprotocol.upper()
        if authprotocol not in ['PLAIN', 'KERBEROS', 'NTLM']:
            raise ValueError(f"Invalid authentication protocol: {authprotocol} Must be one of: PLAIN, KERBEROS, NTLM")

        target = MSSQLTarget(
            ip = hostname, 
            database=database,
            domain= domain,
            port = port
        )

        credential = UniCredential(
            username=username,
            secret=password,
            stype=asyauthSecret.PASSWORD,
            domain=domain,
            protocol=asyauthProtocol.from_string(authprotocol)
        )
        return MSSQLConnectionFactory(target, credential)
    
    