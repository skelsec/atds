from typing import List

class TDS_ORDER:
    TOKEN_TYPE = 0xA9  # ORDER_TOKEN

    def __init__(self) -> None:
        self.length: int = 0
        self.columns: List[int] = []  # List of column numbers in ORDER BY clause

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_ORDER':
        if len(data) < 3:  # Minimum: token(1) + length(2)
            raise ValueError("ORDER data too short")

        # Verify token type
        if data[0] != TDS_ORDER.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0xA9, got {hex(data[0])}")

        packet = TDS_ORDER()
        pos = 1  # Start after token

        # Parse length (2 bytes)
        packet.length = int.from_bytes(data[pos:pos+2], byteorder='little')
        if len(data) < packet.length + 3:  # +3 for token and length bytes
            raise ValueError("Data shorter than specified length")
        pos += 2
        
        # Parse column numbers (2 bytes each)
        end_pos = pos + packet.length
        while pos < end_pos:
            if pos + 2 > end_pos:
                raise ValueError("Incomplete column number")
            col_num = int.from_bytes(data[pos:pos+2], byteorder='little')
            packet.columns.append(col_num)
            pos += 2

        return packet