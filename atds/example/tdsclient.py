import shlex
import asyncio
import traceback

import tabulate

from atds.common.exceptions import TDSError
from atds.cursor import TDSCursor
from atds.common.factory import MSSQLConnectionFactory
from atds.connection import MSSQLConnection
from atds.external.aiocmd.aiocmd import aiocmd

class MSSQLConsole(aiocmd.PromptToolkitCmd):
    def __init__(self, factory: MSSQLConnectionFactory):
        aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
        self.connection: MSSQLConnection = None
        self.factory: MSSQLConnectionFactory = factory
        self.__table_format = 'grid'
        self.__show_query = False
        self.__sql_link = []
        self.__start_server = ''

        """
        sql_link entry format:
        [
            {
                'server': 'server', #server name from the uselink command
                'user': 'user', #the runas query prefix
            }
        ]
        """


    def __handle_error(self, e: Exception):
        traceback.print_exc()
        return False, e


    async def __print_cursor(self, cursor: TDSCursor):
        async for info in cursor.info():
            print(f"{info.pprint()}")
        async for error in cursor.errors():
            print(f"{error.pprint()}")
        cursor.print_table(tablefmt=self.__table_format)
        affected_rows = await cursor.rowcount()
        if affected_rows is not None and affected_rows > 0:
            print(f"Affected rows: {affected_rows}")


    async def do_settableformat(self, tablefmt:str):
        """Changes the output table format for the current session."""
        try:
            tablefmt = tablefmt.lower()
            if tablefmt in tabulate.tabulate_formats:
                self.__table_format = tablefmt
            else:
                print(f'Invalid table format: {tablefmt}.\r\nValid formats are: {", ".join(tabulate.tabulate_formats)}')
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_gettableformat(self):
        """Gets the current output table format for the current session."""
        print(f"Current table format: {self.__table_format}")
        return True, None

    async def do_refreshprompt(self):
        """Refreshes the prompt for the current session."""
        if self.__start_server == '':
            query = """SELECT @@SERVERNAME as 'server'"""
            cursor = await self.query(query, to_print=False)
            result = await cursor.fetch_one()
            if result is not None and result.get('server') is not None:
                self.__start_server = result.get('server')
                
        query = """SELECT system_user as 'user'"""

        user = ''
        try:
            cursor = await self.query(query, to_print=False)
            result = await cursor.fetch_one()
            if result is not None and result.get('user') is not None:
                user = result.get('user')
        except:
            pass
        
        
        link = '->'.join([entry['server'] for entry in self.__sql_link])
        if len(link) > 0:
            link = self.__start_server + '->' + link
        else:
            link = self.__start_server
        
        database = ''
        try:
            cursor = await self.query("SELECT DB_NAME() as 'database'", to_print=False)
            result = await cursor.fetch_one()
            if result is not None and result.get('database') is not None:
                database = result.get('database')
        except:
            pass
        self.prompt = f"[{user}@{link}]:{database}$ "
        return True, None

    async def do_login(self):
        """Logs in to the current server."""
        try:
            self.connection = self.factory.get_connection()
            _, err = await self.connection.connect()
            if err is not None:
                raise err
            await self.do_refreshprompt()
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def query(self, sql:str, rowtype='dict', to_print:bool = True):
        """Executes a query on the current server."""
        query = sql
        if len(self.__sql_link) > 0:
            for entry in self.__sql_link[::-1]:
                s_user = entry['user'].replace("'", "''")
                s_server = entry['server'].replace("'", "''")
                s_query = query.replace("'", "''")
                query = f"EXEC ('{s_user} {s_query}') AT {s_server}"
        if self.__show_query is True:
            print(query)
        cursor = self.connection.get_cursor(rowtype=rowtype)
        await cursor.execute(query)
        if to_print is True:
            await self.__print_cursor(cursor)
        return cursor

    async def executeas(self, query):
        """Executes a query as a different user."""
        if len(self.__sql_link) > 0:
            # change to new user
            self.__sql_link[-1]['user'] = query
        else:
            cursor = await self.query(query)
            return cursor

    async def do_showquery(self):
        """Shows the query in the console."""
        self.__show_query = True
        return True, None

    async def do_hidequery(self):
        """Hides the query in the console."""
        self.__show_query = False
        return True, None

    async def do_executeasuser(self, user:str):
        """Executes a query as a different user."""
        try:
            query = f"""EXECUTE AS USER = '{user}'"""
            await self.executeas(query)
            
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_executeaslogin(self, user:str):
        """Executes a query as a different login."""
        try:
            query = f"""EXECUTE AS LOGIN = '{user}'"""
            await self.executeas(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_uselink(self, server:str):
        """Uses a link to execute future queries on a different server."""
        try:
            if server == 'localhost':
                self.__sql_link = []
                await self.do_refreshprompt()
                return True, None
            elif server == '..':
                self.__sql_link.pop()
                await self.do_refreshprompt()
                return True, None
            else:
                self.__sql_link.append({
                    'server': server,
                    'user': ''
                })
                cursor = await self.query("SELECT system_user as 'user'", to_print=False)
                result = await cursor.fetch_one()
                if result is None or result.get('user') is None:
                    self.__sql_link.pop()
                    print("Failed to get username")
                    return False, None
                print(f"Changed to server: {server} as user: {result.get('user')}")
                await self.do_refreshprompt()
                return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_xpdirtree(self, path:str):
        """Lists files and folders in a directory. Using the xp_dirtree command."""
        try:
            query = f"""EXEC xp_dirtree '{path}'"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_xpcmdshell(self, command:str):
        """Executes a command using the xp_cmdshell command."""
        try:
            await self.query(f"""EXEC xp_cmdshell '{command}'""")
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_dumphashes(self):
        """Dumps the hashes of all users in the master database. Must be admin to use."""
        try:
            await self.query("""
IF ( OBJECT_ID('master..sysxlogins' ) ) <> 0
    SELECT name, password FROM master..sysxlogins WHERE password IS NOT NULL
ELSE IF ( OBJECT_ID('master.sys.sql_logins') ) <> 0
    SELECT name, password_hash FROM master.sys.sql_logins
            """)
            return True, None
        except Exception as e:
            return self.__handle_error(e)


    async def do_enablexpcmdshell(self):
        """Enables the xp_cmdshell command. Must be admin to use."""
        try:
            query = """EXEC master.dbo.sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC master.dbo.sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_disablexpcmdshell(self):
        """Disables the xp_cmdshell command. Must be admin to use."""
        try:
            query = """EXEC master.dbo.sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC master.dbo.sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)
        
    async def do_enumlinks(self):
        """Enumerates all linked servers and linked server logins."""
        try:
            query = """EXEC sp_linkedservers"""
            await self.query(query)
            query = """EXEC sp_helplinkedsrvlogin"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumusers2(self):
        """Enumerates all users in the current database using sp_helpuser."""
        try:
            query = """EXEC sp_helpuser"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumtables(self):
        """Enumerates all tables in all user databases."""
        try:
            query = """
DECLARE @sql NVARCHAR(MAX) = N'';

-- Build dynamic SQL for all user databases
SELECT @sql += 
    'SELECT ''' + name + ''' AS DatabaseName, 
            s.name AS SchemaName, 
            t.name AS TableName 
     FROM ' + QUOTENAME(name) + '.sys.tables t 
     INNER JOIN ' + QUOTENAME(name) + '.sys.schemas s ON t.schema_id = s.schema_id 
     UNION ALL '
FROM sys.databases
WHERE state_desc = 'ONLINE'  -- Exclude offline databases
AND name NOT IN ('master', 'tempdb', 'model', 'msdb');  -- Exclude system databases

-- Ensure @sql is not empty before removing last "UNION ALL"
IF LEN(@sql) > 0
BEGIN
    SET @sql = LEFT(@sql, LEN(@sql) - 10);  -- Safely remove last "UNION ALL"
    EXEC sp_executesql @sql;  -- Execute final SQL
END
ELSE
    PRINT 'No user databases found.';

"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumusers(self):
        """Enumerates all users in the current database using sys.sysusers."""
        try:
            query = """
SELECT 
    name AS [User], 
    SUSER_SNAME(sid) AS [Login] 
FROM sys.sysusers;
"""
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumdatabases(self):
        """Enumerates all databases on the current server."""
        try:
            query = """
SELECT 
    name AS DatabaseName, 
    is_trustworthy_on 
FROM sys.databases;
        """ 
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumowner(self):
        """Enumerates all databases on the current server and their owners."""
        try:
            query = """
SELECT 
    name AS [Database], 
    SUSER_SNAME(owner_sid) AS [Owner] 
FROM sys.databases;
        """
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumlogins(self):
        """Enumerates all logins on the current server."""
        try:
            query = """
SELECT 
    sp.name,
    sp.type_desc,
    sp.is_disabled, 
    sl.sysadmin, 
    sl.securityadmin, 
    sl.serveradmin, 
    sl.setupadmin, 
    sl.processadmin, 
    sl.diskadmin, 
    sl.dbcreator, 
    sl.bulkadmin
FROM master.sys.server_principals sp
LEFT JOIN master.sys.syslogins sl 
    ON sl.sid = sp.sid
        WHERE sp.type IN ('S', 'E', 'X', 'U', 'G');
        """
            await self.query(query)
            return True, None
        except Exception as e:
            return self.__handle_error(e)
    
    async def do_enumimpersonate(self):
        """Enumerates all databases on the current server and their impersonate permissions."""
        try:
            cursor = self.connection.get_cursor(rowtype='dict')
            await cursor.execute("select name from sys.databases")
            for row in cursor:
                try:
                    query = f"""
USE [{row['name']}];

SELECT 
    'USER' AS execute_as, 
    DB_NAME() AS database_name,
    pe.permission_name,
    pe.state_desc, 
    grantee.name AS grantee, 
    grantor.name AS grantor
FROM sys.database_permissions AS pe
JOIN sys.database_principals AS grantee 
    ON pe.grantee_principal_id = grantee.principal_Id
JOIN sys.database_principals AS grantor 
    ON pe.grantor_principal_id = grantor.principal_Id
WHERE pe.permission_name = 'IMPERSONATE';

                    """
                    perm_result = await self.query(query, to_print=False)
                    rowcount = await perm_result.rowcount()
                    if rowcount > 0:
                        print(f"Database: {row['name']}")
                        perm_result.print_table(tablefmt=self.__table_format)
                        print()
                    else:
                        print(f"No impersonate permissions found for database: {row['name']}")
                except TDSError as e:
                    pass

            query = """
            SELECT 
    'LOGIN' AS execute_as, 
    NULL AS database_name, 
    pe.permission_name, 
    pe.state_desc, 
    grantee.name AS grantee, 
    grantor.name AS grantor
FROM sys.server_permissions AS pe
JOIN sys.server_principals AS grantee 
    ON pe.grantee_principal_id = grantee.principal_id
JOIN sys.server_principals AS grantor 
    ON pe.grantor_principal_id = grantor.principal_id
WHERE pe.class = 100  -- Server-level permissions
AND pe.permission_name = 'IMPERSONATE';
            """
            cursor = await self.query(query, to_print=False)
            rowcount = await cursor.rowcount()
            if rowcount > 0:
                print("Login impersonate permissions:")
                cursor.print_table(tablefmt=self.__table_format)
            else:
                print("No login impersonate permissions found.")
            return True, None
        except Exception as e:
            return self.__handle_error(e)


    async def do_query(self, sql:str, to_print:bool = True):
        """Executes a query on the current server."""
        try:
            await self.query(sql, to_print=to_print)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_queryfile(self, file:str):
        """Executes a query from a file."""
        try:
            with open(file, 'r') as f:
                sql = f.read()
            await self.query(sql)
            print(f"Executed query from file: {file}")
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_changedb(self, db:str):
        """Changes the current database."""
        try:
            await self.connection.batch(f"USE {db}")
            await self.do_refreshprompt()
            print(f"Changed to database: {db}")
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_enumall(self):
        """Runs all the enum commands."""
        try:
            # run all the enum commands
            await self.do_enumlinks()
            await self.do_enumusers()
            await self.do_enumusers2()
            await self.do_enumlogins()
            await self.do_enumimpersonate()
            await self.do_enumdatabases()
            await self.do_enumowner()
            await self.do_enumtables()
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_exit(self):
        """Exits the current session."""
        try:
            print('EXIT CALLED')
            await self.connection.close()
            print('EXIT FINISHED')
            return True, None
        except Exception as e:
            return self.__handle_error(e)

    async def do_cursortest(self):
        """Tests the cursor stream functionality."""
        try:
            cursor = self.connection.get_cursor(stream=True, rowtype='dict')
            await cursor.execute("select 1 as a, 2 as b")
            async for row in cursor:
                print(row)
            return True, None
        except Exception as e:
            return self.__handle_error(e)

async def amain(args):
    factory = MSSQLConnectionFactory.from_url(args.url)
    console = MSSQLConsole(factory)
    
    if len(args.commands) == 0:
        if args.no_interactive is True:
            print('Not starting interactive!')
            return
        res = await console._run_single_command('login', [])
        if res is False:
            return
        await console.run()
    else:
        for command in args.commands:
            if command == 'i':
                await console.run()
                return
            cmd = shlex.split(command)
            res = await console._run_single_command(cmd[0], cmd[1:])
            if res is False:
                return

def main():
    import argparse
    import platform

    parser = argparse.ArgumentParser(description='MS LDAP library')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
    parser.add_argument('-n', '--no-interactive', action='store_true')
    parser.add_argument('url', help='Connection string in URL format.')
    parser.add_argument('commands', nargs='*', help="Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

    args = parser.parse_args()

    asyncio.run(amain(args))

if __name__ == '__main__':
    main()