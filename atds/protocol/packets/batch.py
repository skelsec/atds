

class TDS_BATCH:
    def __init__(self):
        self.length: int = 0
        self.sql: str = ""

    def to_bytes(self) -> bytes:
        return self.sql.encode('utf-16-le')