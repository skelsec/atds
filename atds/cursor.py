import asyncio
import datetime
import re
import warnings
from typing import Any, List, Tuple
from enum import Enum
from atds.protocol.packets.tokenstream import TDSTokenType
from atds.protocol.packets.tokenstream.done import DoneStatus
from atds.protocol.packets.tokenstream.colmetadata import TDS_COLMETADATA
from atds.protocol.packets.tokenstream.error import TDS_ERROR
from atds.protocol.packets.tokenstream.done import TDS_DONE
from atds.protocol.packets.tokenstream.order import TDS_ORDER

from tabulate import tabulate

from collections import namedtuple


class RowType(Enum):
    LIST = 0
    DICT = 1
    TUPLE = 2

class TDSCursor:
    def __init__(self, connection:'MSSQLConnection', stream:bool = False, rowtype:RowType = RowType.LIST):
        self.__read_task = None
        self.connection = connection
        self._rows = []
        self._columns = []
        self._column_names = []
        self._affected_rows = 0
        self._status = 0
        self._lastrowid = None
        self._errors = []
        self._info = []
        self._order = []
        self._returnstatus = []
        self._returnvalue = []
        self._stream = stream
        self._row_stream_queue = asyncio.Queue()

        self.__events = {
            'colmetadata': asyncio.Event(),
            'done': asyncio.Event(),
        }

        self.__events['done'].set()

        if isinstance(rowtype, str):
            if rowtype.upper() in RowType.__members__:
                self._rowtype = RowType[rowtype.upper()]
            else:
                raise ValueError(f"Invalid row type: {rowtype}. Valid types are: {', '.join([t.name for t in RowType])}")
        else:
            self._rowtype = rowtype


    def reset_state(self):
        self._rows = []
        self._columns = []
        self._column_names = []
        self._affected_rows = 0
        self._status = 0
        self._errors = []
        self._info = []
        self._lastrowid = None
        self._order = []
        self._returnstatus = []
        self._returnvalue = []
        self.__events['done'].clear()
        self._row_stream_queue = asyncio.Queue()

    async def close(self):
        if self._stream is False:
            return
        if self.more_rows() is True:
            # read all rows from the stream
            async for row in self.fetch_all():
                a = 1
        await self.__events['done'].wait()
        self._row_stream_queue.put_nowait(None)

    def __parse_params(self, sql: str) -> tuple[bool, set, bool]:
        """
        Parse SQL to detect parameter style and names.
        Returns: (has_params, param_names, is_named)
        """
        named_params = set()
        
        # Step 1: Find DECLARE'd variables (avoid falsely treating them as parameters)
        declare_pattern = re.compile(r'DECLARE\s+(@[A-Za-z0-9_]+)', re.IGNORECASE)
        declared_vars = {m.group(1) for m in declare_pattern.finditer(sql)}
        
        # Step 2: Find @parameters but exclude:
        #   - System variables (@@var)
        #   - Declared variables (e.g., `DECLARE @myvar INT`)
        param_matches = re.finditer(r'(?<!@)@[A-Za-z0-9_]+', sql)  # Ignore @@system_vars
        for match in param_matches:
            param = match.group()
            if param not in declared_vars:
                named_params.add(param.lstrip('@'))

        # Step 3: Find positional parameters (?)
        positional_params = len(re.findall(r'(?<!@)\?(?=[^\']*(?:\'[^\']*\'[^\']*)*$)', sql))

        # Step 4: Error if mixed parameter styles
        if named_params and positional_params:
            raise ValueError("Cannot mix named and positional parameters")

        return (bool(named_params or positional_params), 
                named_params or set(range(positional_params)), 
                bool(named_params))

    def __format_param(self, value: Any) -> str:
        """
        Format parameter value based on its type
        """
        if value is None:
            return 'NULL'
        elif isinstance(value, bool):
            return '1' if value else '0'
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, datetime.datetime):
            # Format datetime as 'YYYY-MM-DD HH:MM:SS.mmm'
            return f"'{value.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}'"
        elif isinstance(value, datetime.date):
            return f"'{value.strftime('%Y-%m-%d')}'"
        elif isinstance(value, bytes):
            # Convert bytes to hex string
            return f"0x{value.hex()}"
        elif isinstance(value, str):
            # Escape single quotes and properly quote the string
            nv = value.replace("'", "''")
            return f"'{nv}'"
        else:
            raise ValueError(f"Unsupported parameter type: {type(value)}")

    async def __execute_and_process(self, sql:str):
        try:
            async for packettype, tokentype, token in self.connection.batch_raw(sql):
                #read and process every packet until colmetadata, then wait for the user to call fetch_one or fetch_all
                if tokentype == TDSTokenType.COLMETADATA:
                    self._columns.append(token)
                    self._column_names.extend(token.column_names)
                elif tokentype in [TDSTokenType.DONE, TDSTokenType.DONEINPROC, TDSTokenType.DONEPROC]:
                    self._affected_rows = token.row_count
                    self._status = token.status
                    if token.status == DoneStatus.DONE_FINAL:
                        break
                elif tokentype == TDSTokenType.ROW:
                    if self._stream:
                        await self._row_stream_queue.put(token.values)
                    else:
                        self._rows.append(token.values)
                elif tokentype == TDSTokenType.ORDER:
                    self._order.append(token)
                elif tokentype == TDSTokenType.RETURNSTATUS:
                    self._returnstatus.append(token)
                elif tokentype == TDSTokenType.RETURNVALUE:
                    self._returnvalue.append(token)
                elif tokentype == TDSTokenType.ERROR:
                    self._errors.append(token)
                elif tokentype == TDSTokenType.INFO:
                    self._info.append(token)
        except Exception as e:
            raise e
        finally:
            self.__events['done'].set()
            self._row_stream_queue.put_nowait(None)

    async def execute(self, sql: str, params: List[Any] | dict = None):
        """
        Execute a SQL query with parameters
        
        Args:
            sql: SQL query string
            params: Query parameters (list for positional, dict for named)
        """
        if self.more_rows() is True:
            raise ValueError("Cannot execute a new query while a previous query is still being processed")
        self.reset_state()

        if not sql.strip():
            raise ValueError("Empty SQL query")

        # If no params provided, check if query expects parameters
        has_params, param_names, is_named = self.__parse_params(sql)
        if not has_params:
            if params:
                raise ValueError("Parameters provided but SQL has no parameter placeholders")
            self.__read_task = asyncio.create_task(self.__execute_and_process(sql))
            if self._stream is False:
                await self.__events['done'].wait()
            return

        # Validate parameters were provided if needed
        if has_params and not params:
            raise ValueError("SQL contains parameters but no values provided")

        # Validate parameter types and counts
        if is_named:
            if not isinstance(params, dict):
                raise ValueError("Named parameters required but got a list")
            
            # Validate all required parameters are provided
            missing_params = param_names - set(k.lstrip('@') for k in params.keys())
            if missing_params:
                raise ValueError(f"Missing parameters: {missing_params}")
            
            # Extra parameters are ignored but might indicate a bug
            extra_params = set(k.lstrip('@') for k in params.keys()) - param_names
            if extra_params:
                warnings.warn(f"Extra parameters provided but not used: {extra_params}")

            # Build parameter dictionary with proper formatting
            formatted_params = {
                f"@{name}": self.__format_param(params[name.lstrip('@')])
                for name in param_names
            }

            # Replace parameters in query
            pattern = '|'.join(map(re.escape, formatted_params.keys()))
            final_sql = re.sub(
                f'({pattern})',
                lambda m: formatted_params[m.group()],
                sql
            )

        else:  # Positional parameters
            if not isinstance(params, (list, tuple)):
                raise ValueError("List of parameters required but got a dictionary")
            
            if len(params) != len(param_names):
                raise ValueError(
                    f"Wrong number of parameters. Expected {len(param_names)}, got {len(params)}"
                )

            # Format all parameters first
            formatted_params = [self.__format_param(value) for value in params]
            
            # Replace ? with parameters one by one
            parts = sql.split('?')
            if len(parts) != len(formatted_params) + 1:
                raise ValueError("Parameter count mismatch")
                
            final_sql = ''
            for i, part in enumerate(parts[:-1]):
                final_sql += part + str(formatted_params[i])
            final_sql += parts[-1]

        # Execute the parameterized query
        self.__read_task = asyncio.create_task(self.__execute_and_process(final_sql))
        if self._stream is False:
            await self.__events['done'].wait()
        return

    async def column_names(self):
        if self._stream is False:
            return self._column_names
        # wait for the colmetadata event to be set or done event to be set
        await asyncio.wait([self.__events['colmetadata'].wait(), self.__events['done'].wait()])
        return self._column_names

    async def lastrowid(self):
        if self._stream is False:
            return self._lastrowid
        await self.__events['done'].wait()
        return self._lastrowid

    async def rowcount(self):
        await self.__events['done'].wait()
        return len(self._rows)

    async def info(self):
        await self.__events['done'].wait()
        for info in self._info:
            yield info

    async def errors(self):
        await self.__events['done'].wait()
        for error in self._errors:
            yield error

    def __process_row(self, row:List[Tuple[Any, ...]]):
        # convert the row to the user-specified format
        if self._rowtype == RowType.LIST:
            return row
        elif self._rowtype == RowType.TUPLE:
            # named tuple
            return namedtuple('Row', self._column_names)(*row)
        elif self._rowtype == RowType.DICT:
            return dict(zip(self._column_names, row))

    def more_rows(self):
        if self._stream is False:
            return len(self._rows) > 0
        else:
            if self.__events['done'].is_set() and self._row_stream_queue.empty():
                return False
            return True

    def check_rows_return(func):
        """Decorator to check for more rows before and after fetch operations that return a single value"""
        async def wrapper(self, *args, **kwargs):
            if not self.more_rows():
                return None
            
            result = await func(self, *args, **kwargs)
            
            if not self.more_rows():
                # Clean up any resources if needed
                self._rows = []  # Clear any remaining row data
                self.__events['done'].clear()
                self.__events['colmetadata'].clear()
            
            return result
        return wrapper

    def check_rows_iter(func):
        """Decorator to check for more rows before and after fetch operations that yield values"""
        async def wrapper(self, *args, **kwargs):
            if not self.more_rows():
                return
            
            async for item in func(self, *args, **kwargs):
                yield item
            
            if not self.more_rows():
                # Clean up any resources if needed
                self._rows = []  # Clear any remaining row data
                self.__events['done'].clear()
                self.__events['colmetadata'].clear()
        
        return wrapper

    @check_rows_return
    async def fetch_one(self):
        if self._stream is False:
            row = self._rows.pop(0) if self._rows else None
        else:
            row = await self._row_stream_queue.get()
        if row is None:
            return None
        return self.__process_row(row)
    
    @check_rows_iter
    async def fetch_all(self):
        if self._stream is False:
            for row in self._rows:
                yield self.__process_row(row)
        else:
            while True:
                row = await self._row_stream_queue.get()
                if row is None:
                    break
                yield self.__process_row(row)

    @check_rows_iter
    async def fetch_many(self, size:int):
        if self._stream is False:
            for row in self._rows[:size]:
                yield self.__process_row(row)
        else:
            for _ in range(size):
                row = await self._row_stream_queue.get()
                if row is None:
                    break
                yield self.__process_row(row)

    def get_table(self, with_header:bool = True, tablefmt:str = 'grid'):
        if self._stream is True:
            raise ValueError("Cannot get table from streamed cursor")
        header = []
        if with_header and len(self._column_names) > 0:
            header = self._column_names
        rows = []
        for row in self._rows:
            # convert row elements to hex if they are bytes
            for i, element in enumerate(row):
                if isinstance(element, bytes):
                    row[i] = f"0x{element.hex()}"
            rows.append(row)
        return tabulate(rows, headers=header, tablefmt=tablefmt)

    def print_table(self, with_header:bool = True, tablefmt:str = 'grid'):
        if self._stream is True:
            raise ValueError("Cannot print table from streamed cursor")
        print(self.get_table(with_header, tablefmt))

    def __aiter__(self):
        return self

    async def __anext__(self):
        row = await self.fetch_one()
        if row is None:
            raise StopAsyncIteration
        return row

    def __iter__(self):
        if self._stream is True:
            raise ValueError("Cannot iterate over streamed cursor in a blocking manner")
        return self

    def __next__(self):
        if self._stream is True:
            raise ValueError("Cannot iterate over streamed cursor in a blocking manner")
        if len(self._rows) == 0:
            raise StopIteration
        return self.__process_row(self._rows.pop(0))

class QueryResult:
    def __init__(self):
        self.rows = []
        self.columns = []
        self.column_names = []
        self.affected_rows = 0
        self.status = 0
        self.error = None
        self.warnings = []
        self.done:TDS_DONE = None

    def add_row(self, row:List[Tuple[Any, ...]]):
        self.rows.append(row)

    def add_colmetadata(self, token:TDS_COLMETADATA):
        self.columns.append(token)
        self.column_names.extend(token.column_names)

    def add_warning(self, warning:str):
        self.warnings.append(warning)

    def add_error(self, error:TDS_ERROR):
        self.error = error

    def add_done(self, token:TDS_DONE):
        self.affected_rows = token.row_count
        self.done = token
        if token.status == DoneStatus.DONE_ERROR:
            raise self.error.as_exception

    def add_order(self, token:TDS_ORDER):
        self.order = token

    def print_warnings(self):
        for warning in self.warnings:
            print(warning)

    def print_error(self):
        print(self.error)
    
    def get_table(self, with_header:bool = True):
        header = []
        if with_header and len(self.column_names) > 0:
            header = self.column_names
        return tabulate(self.rows, headers=header, tablefmt='grid')

    def print_table(self, with_header:bool = True):
        print(self.get_table(with_header))

    def __str__(self):
        t = self.get_table()
        t += f"\r\nAffected rows: {self.affected_rows}\r\n"
        return t
