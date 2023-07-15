from interceptors.NetInterceptor import NetInterceptor
import regex as re
import io
import struct

class MCProtocolTools:
    @staticmethod
    def readVarInt(iostream):
        SEGMENT_BITS = 0x7F
        CONTINUE_BIT = 0x80
        value = 0
        position = 0
        currentbyte = 0

        raw_data = b""

        while True:
            currentbyte = iostream.read(1)[0]
            raw_data += bytes([currentbyte])

            value |= (currentbyte & SEGMENT_BITS) << position
            position += 7
            if not (currentbyte & CONTINUE_BIT):
                break
            if position > 32:
                raise ValueError("VarInt is too big")
        
        return value, raw_data

    @staticmethod
    def writeVarInt(iostream, value):
        SEGMENT_BITS = 0x7F
        CONTINUE_BIT = 0x80
        length_bytes = 0
        while True:
            temp = value & SEGMENT_BITS
            value >>= 7
            if value != 0:
                temp |= CONTINUE_BIT
            iostream.write(bytes([temp]))
            length_bytes += 1
            if value == 0:
                break
        return length_bytes

class MCHandshakeInterceptor(NetInterceptor):
    def __init__(self, server_address, replacement_addr, replacement_port) -> None:
        self.serverbound_patterns = [
            {
                "type": "include",
                "pattern": server_address.encode(),
                "handler": self.__handle_handshake
            }
        ]
        self.clientbound_patterns = []

        self.replacement_addr = replacement_addr
        self.replacement_port = replacement_port
    
    def __handle_handshake(self, packet):
        packet_ = io.BytesIO(packet)
        
        d2r = b"" # data to replace

        packet_length, d_offset = MCProtocolTools.readVarInt(packet_)
        d_offset_from_beginning = len(d_offset)
        
        packet_id, = packet_.read(1)

        protocol_version, _ = MCProtocolTools.readVarInt(packet_)
        strlen, d = MCProtocolTools.readVarInt(packet_)
        d2r += d
        server_address = packet_.read(strlen)
        d2r += server_address

        server_port_raw = packet_.read(2)
        server_port, = struct.unpack(">H", server_port_raw)
        d2r += server_port_raw

        next_state, _ = MCProtocolTools.readVarInt(packet_)
        # print(f"MCHandshakePacket(server_address=\"{server_address.decode()}\", server_port={server_port}, next_state={next_state}, protocol_version={protocol_version})")
        
        new_data = io.BytesIO()
        lb = MCProtocolTools.writeVarInt(new_data, len(self.replacement_addr))
        new_data.write(self.replacement_addr.encode())
        new_data.write(struct.pack(">H", self.replacement_port))
        new_data.seek(0)

        newdomainlen = len(self.replacement_addr.encode()) + lb
        olddomainlen = len(d) + strlen

        packet = packet.replace(d2r, new_data.read())
        new_packet_length = packet_length + (newdomainlen - olddomainlen)
        new_data = io.BytesIO()
        MCProtocolTools.writeVarInt(new_data, new_packet_length)
        new_data.seek(0)

        packet = new_data.read() + packet[d_offset_from_beginning:]

        return packet 

    def handle_serverbound_chunk(self, packet):
        for pattern in self.serverbound_patterns:
            if pattern["type"] == "include":
                if pattern["pattern"] in packet:
                    return pattern["handler"](packet)
            elif pattern["type"] == "regex":
                if re.search(pattern, packet):
                    return pattern["handler"](packet)
        return packet

    def handle_clientbound_chunk(self, packet):
        for pattern in self.clientbound_patterns:
            if pattern["type"] == "include":
                if pattern["pattern"] in packet:
                    return pattern["handler"](packet)
            elif pattern["type"] == "regex":
                if re.search(pattern, packet):
                    return pattern["handler"](packet)
        return packet