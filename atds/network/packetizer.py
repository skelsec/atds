from asysocks.unicomm.common.packetizers import Packetizer
from atds.protocol.packets import TDSPacket

class TDSPacketizer(Packetizer):
    def __init__(self) -> None:
        Packetizer.__init__(self, 65535)
        self.in_buffer = b''
    
    def process_buffer(self):
        while True:
            if len(self.in_buffer) < 8:
                break
            total_length = TDSPacket.get_total_length(self.in_buffer)
            if total_length > len(self.in_buffer):
                break
            packet = TDSPacket.from_bytes(self.in_buffer[:total_length])
            self.in_buffer = self.in_buffer[total_length:]
            
            yield packet
            

    async def data_out(self, data:bytes):
        yield data

    async def data_in(self, data:bytes):
        if data is None:
            yield data

        self.in_buffer += data

        for packet in self.process_buffer():
            yield packet