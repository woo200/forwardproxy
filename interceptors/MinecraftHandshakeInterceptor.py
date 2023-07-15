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
                "packet_id": 0x00,
                "handler": self.__handle_handshake_sb
            }
        ]
        self.clientbound_patterns = []
        # self.clientbound_patterns = [
        #     {
        #         "packet_id": 0x00,
        #         "handler": self.__handle_handshake_cb
        #     }
        # ]

        self.replacement_addr = replacement_addr
        self.replacement_port = replacement_port

        self.handshake_state = 0
    
    def __generate_packet_with_header(self, packet_id, packet_data):
        d = io.BytesIO()

        MCProtocolTools.writeVarInt(d, len(packet_data) + 1)
        d.write(bytes([packet_id]))

        return d.getvalue() + packet_data
    
    def __handle_login_packet(self, packet_len, packet_iostream, raw_packet):
        pb = io.BytesIO()

        username_len, dl1 = MCProtocolTools.readVarInt(packet_iostream)
        username = packet_iostream.read(username_len).decode("utf-8")
        has_uuid, = packet_iostream.read(1)
        uuid = None
        
        if has_uuid == 0x01:
            uuid = packet_iostream.read(16)
        
        if len(dl1) + username_len + 1 + (16 if has_uuid == 0x01 else 0) != packet_len:
            return False, None
        
        # rebuild packet
        MCProtocolTools.writeVarInt(pb, username_len)
        pb.write(username.encode("utf-8"))
        pb.write(bytes([has_uuid]))
        if has_uuid == 0x01:
            pb.write(uuid)
        
        return True, self.__generate_packet_with_header(0x00, pb.getvalue())

    def __handle_handshake_sb(self, packet_len, packet_iostream, raw_packet):
        if self.handshake_state == 1:
            return True, self.__generate_packet_with_header(0x00, b'')
        if self.handshake_state == 2:
            return self.__handle_login_packet(packet_len, packet_iostream, raw_packet)
        
        # Initial Handshake packet
        protocol_version, dl1 = MCProtocolTools.readVarInt(packet_iostream)
        server_address_len, dl2 = MCProtocolTools.readVarInt(packet_iostream)
        server_address = packet_iostream.read(server_address_len).decode("utf-8")

        dl3 = packet_iostream.read(2)
        server_port, = struct.unpack(">H", dl3)
        next_state, dl4 = MCProtocolTools.readVarInt(packet_iostream)

        spec_packet_len = len(dl1) + len(dl2) + len(dl3) + len(dl4) + server_address_len

        if len(dl1) + len(dl2) + len(dl3) + len(dl4) + server_address_len != packet_len:
            return False, None
        
        # rebuild packet
        new_packet = io.BytesIO()

        server_address = self.replacement_addr if self.replacement_addr != None else server_address
        server_port = self.replacement_port if self.replacement_port != None else server_port
        
        MCProtocolTools.writeVarInt(new_packet, protocol_version)
        MCProtocolTools.writeVarInt(new_packet, len(server_address))
        new_packet.write(server_address.encode("utf-8"))
        new_packet.write(struct.pack(">H", server_port))
        MCProtocolTools.writeVarInt(new_packet, next_state)

        self.handshake_state = next_state

        return True, self.__generate_packet_with_header(0x00, new_packet.getvalue())

    def handle_serverbound_chunk(self, packet):
        packet_ = io.BytesIO(packet) # We do not know yet if this is a minecraft packet
        totaldata = b""

        while True:
            packet_length, _ = MCProtocolTools.readVarInt(packet_)
            packet_id, = packet_.read(1)
            packet_identified = False

            for pattern in self.serverbound_patterns:
                if pattern["packet_id"] == packet_id: # subpacket identified
                    valid_packet, new_packet = pattern["handler"](packet_length - 1, packet_, packet)
                    
                    if not valid_packet: # invalid subpacket, stop processing
                        return packet

                    totaldata += new_packet # append new subpacket
                    packet_identified = True 
                    break
            
            if not packet_identified: # subpacket not identified, run some checks
                if packet_length > len(packet): # invalid subpacket, stop processing
                    return packet
                if packet_length - 1 > len(packet) - packet_.tell(): # invalid subpacket, stop processing
                    return packet

                totaldata += packet_.read(packet_length - 1) # probably valid subpacket, append it

            if packet_.tell() >= len(packet): # end of packet
                break

        return totaldata # return new packet

    def handle_clientbound_chunk(self, packet):
        for pattern in self.clientbound_patterns:
            if pattern["type"] == "include":
                if pattern["pattern"] in packet:
                    return pattern["handler"](packet)
            elif pattern["type"] == "regex":
                if re.search(pattern, packet):
                    return pattern["handler"](packet)
        return packet