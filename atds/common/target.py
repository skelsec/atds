
import random
from asysocks.unicomm.common.target import UniTarget, UniProto
from urllib.parse import urlparse, parse_qs
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one


mssql_target_url_params = {
    'sqlvermajor' : int_one,
    'sqlverminor' : int_one,
    'sqlverbuild' : int_one,
    'sqlinstance' : str_one,
    'sqlthreadid' : int_one,
    'sqlencrypt' : bool_one,
    'sqlpacketsize' : int_one,
    'sqlappname' : str_one,
    'sqlclientname' : str_one,
    'sqlpid' : int_one,
}


class MSSQLTarget(UniTarget):

    def __init__(self, ip, port = 1433, protocol = UniProto.CLIENT_TCP, proxies = None, timeout = 10, 
                    sqlvermajor = 15, sqlverminor = 0, sqlverbuild = 4123, sqlinstance = 'MSSQLServer', sqlthreadid = None, 
                    sqlencrypt = True, dns:str=None, dc_ip:str = None, domain:str = None, hostname:str = None, sqlpacketsize:int = 32764,
                    sqlappname:str = 'atds', sqlclientname:str = 'atds', sqlpid:int = None, database:str = None):
        UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns)
        self.database = database
        self.sqlvermajor = sqlvermajor
        self.sqlverminor = sqlverminor
        self.sqlverbuild = sqlverbuild
        self.sqlinstance = sqlinstance
        self.sqlthreadid = sqlthreadid
        self.sqlencrypt = sqlencrypt
        self.sqlpacketsize = sqlpacketsize
        self.sqlappname = sqlappname
        self.sqlclientname = sqlclientname
        self.sqlpid = sqlpid

        if sqlthreadid is None:
            self.sqlthreadid = random.randint(0, 0xFFFFFFFF)
        if sqlpid is None:
            self.sqlpid = random.randint(0, 0xFFFFFFFF) 
    
    def to_target_string(self):
        domain = self.domain
        if self.domain is None and self.hostname is not None:
            domain = self.hostname.split('.', 1)[-1]
        return 'MSSQLSvc/%s@%s:%s' % (self.get_hostname_or_ip(), domain, self.port)

    def get_host(self):
        return 'mssql://%s:%s' % (self.get_hostname_or_ip(), self.port)

    def is_ssl(self):
        return self.protocol == UniProto.CLIENT_SSL_TCP
    
    @staticmethod
    def from_url(connection_url):
        url_e = urlparse(connection_url)
        schemes = []
        for item in url_e.scheme.upper().split('+'):
            schemes.append(item.replace('-','_'))
        if schemes[0] == 'MSSQL':
            protocol = UniProto.CLIENT_TCP
            port = 1433
        else:
            raise Exception('Unknown protocol! %s' % schemes[0])
        
        if url_e.port:
            port = url_e.port
        if port is None:
            raise Exception('Port must be provided!')
        
        path = None
        if url_e.path not in ['/', '', None]:
            path = url_e.path
        
        unitarget, extraparams = UniTarget.from_url(connection_url, protocol, port, mssql_target_url_params)
        database = path
        sqlvermajor = extraparams.get('sqlvermajor', 15)
        sqlverminor = extraparams.get('sqlverminor', 0)
        sqlverbuild = extraparams.get('sqlverbuild', 4123)
        sqlinstance = extraparams.get('sqlinstance', 'MSSQLServer')
        sqlthreadid = extraparams.get('sqlthreadid', random.randint(0, 0xFFFFFFFF))
        sqlencrypt = extraparams.get('sqlencrypt', True)
        sqlpacketsize = extraparams.get('sqlpacketsize', 32764)
        sqlappname = extraparams.get('sqlappname', None)
        sqlclientname = extraparams.get('sqlclientname', None)
        sqlpid = extraparams.get('sqlpid', None)

        target = MSSQLTarget(
            unitarget.ip, 
            port = unitarget.port, 
            protocol = unitarget.protocol, 
            database = database, 
            proxies = unitarget.proxies, 
            timeout = unitarget.timeout, 
            dns = unitarget.dns, 
            dc_ip = unitarget.dc_ip, 
            domain = unitarget.domain, 
            hostname = unitarget.hostname,
            sqlvermajor = sqlvermajor,
            sqlverminor = sqlverminor,
            sqlverbuild = sqlverbuild,
            sqlinstance = sqlinstance,
            sqlthreadid = sqlthreadid,
            sqlencrypt = sqlencrypt,
            sqlpacketsize = sqlpacketsize,
            sqlappname = sqlappname,
            sqlclientname = sqlclientname,
            sqlpid = sqlpid,
        )
        return target

    
    def __str__(self):
        t = '==== MSSQLTarget ====\r\n'
        for k in self.__dict__:
            t += '%s: %s\r\n' % (k, self.__dict__[k])
            
        return t