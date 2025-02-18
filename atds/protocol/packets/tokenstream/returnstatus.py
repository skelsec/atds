

class TDS_RETURNSTATUS:
    TOKEN_TYPE = 0x79  # RETURNSTATUS_TOKEN

    def __init__(self) -> None:
        self.value: int = 0  # LONG value, cannot be NULL
        self.length: int = 0

    @staticmethod
    def from_bytes(data: bytes) -> 'TDS_RETURNSTATUS':
        if len(data) < 5:  # Minimum: token(1) + value(4)
            raise ValueError("RETURNSTATUS data too short")

        # Verify token type
        if data[0] != TDS_RETURNSTATUS.TOKEN_TYPE:
            raise ValueError(f"Invalid TOKEN_TYPE: expected 0x79, got {hex(data[0])}")

        packet = TDS_RETURNSTATUS()
        
        # Parse value (4 bytes, signed long)
        packet.value = int.from_bytes(data[1:5], byteorder='little', signed=True)
        packet.length = 5
        return packet