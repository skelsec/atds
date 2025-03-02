from atds.protocol.packets.tokenstream.error import TDS_ERROR

class TDSException(Exception):
    pass

class TDSError(TDSException):
    def __init__(self, token: TDS_ERROR):
        self.token = token
        self.message = token.message
        self.server_name = token.server_name
        self.proc_name = token.proc_name
        self.line_number = token.line_number
        self.severity = token.severity
        self.number = token.number
        self.state = token.state

    def __str__(self):
        return f'[{self.severity.name}] "{self.message}"'

class TDSWarning(TDSException):
    pass

