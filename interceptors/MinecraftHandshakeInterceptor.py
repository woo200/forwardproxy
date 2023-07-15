from interceptors.NetInterceptor import NetInterceptor
import regex as re
import io
import uuid
import struct
import time
from loguru import logger

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
    def __init__(self, replacement_addr, replacement_port) -> None:
        self.serverbound_patterns = [
            {
                "packet_id": 0x00,
                "handler": self.__handle_handshake_sb
            }, 
            {
                "packet_id": 0x01,
                "handler": self.__handle_ping_packet_sb
            }
        ]
        # self.clientbound_patterns = []
        self.clientbound_patterns = [
            {
                "packet_id": 0x00,
                "handler": self.__handle_handshake_cb
            }, 
            {
                "packet_id": 0x01,
                "handler": self.__handle_ping_packet_cb
            }
        ]

        self.replacement_addr = replacement_addr
        self.replacement_port = replacement_port

        self.handshake_state = 0
        self.ping_id = 0
        self.username = ""
        self.uuid = ""
        self.logged_in = False
    
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
        player_uuid = None
        
        if has_uuid == 0x01:
            player_uuid = packet_iostream.read(16)
        
        if len(dl1) + username_len + 1 + (16 if has_uuid == 0x01 else 0) != packet_len:
            return False, None
        
        uuid_str = ""
        if has_uuid == 0x01:
            uuid_str = f" [{str(uuid.UUID(bytes=player_uuid))}]"
        logger.info(f"[{self.client_name}] Player {username}{uuid_str} has sent login packet")

        # rebuild packet
        MCProtocolTools.writeVarInt(pb, username_len)
        pb.write(username.encode("utf-8"))
        pb.write(bytes([has_uuid]))
        if has_uuid == 0x01:
            pb.write(player_uuid)

        self.logged_in = True
        
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

    def __handle_handshake_cb(self, packet_len, packet_iostream, raw_packet):
        if self.handshake_state == 1: # status
            json_len, dl1 = MCProtocolTools.readVarInt(packet_iostream)
            json_data = packet_iostream.read(json_len).decode("utf-8")
            if len(dl1) + json_len != packet_len:
                return False, None
            
            # rebuild packet
            new_packet = io.BytesIO()
            MCProtocolTools.writeVarInt(new_packet, json_len)
            new_packet.write(json_data.encode("utf-8"))

            return True, self.__generate_packet_with_header(0x00, new_packet.getvalue())
        elif self.handshake_state == 2: # login
            return self.__handle_login_packet(packet_len, packet_iostream, raw_packet)
        return False, None
    
    def __handle_ping_packet_sb(self, packet_len, packet_iostream, raw_packet):
        if self.handshake_state == 1:
            payload, = struct.unpack(">Q", packet_iostream.read(8))
            if 8 != packet_len:
                return False, None
            self.ping_id = [payload, time.time()]
            logger.info(f"[{self.client_name}] Client sent ping request")

            return True, self.__generate_packet_with_header(0x01, struct.pack(">Q", payload))
        return False, None
    
    def __handle_ping_packet_cb(self, packet_len, packet_iostream, raw_packet):
        if self.handshake_state == 1:
            payload, = struct.unpack(">Q", packet_iostream.read(8))
            if 8 != packet_len:
                return False, None
            if payload == self.ping_id[0]:
                ping = round((time.time() - self.ping_id[1]) * 1000)
                logger.info(f"[{self.client_name}] Server Ping Response ({ping}ms)")

            return True, self.__generate_packet_with_header(0x01, struct.pack(">Q", payload))
        return False, None
    def handle_serverbound_chunk(self, packet):
        if self.logged_in:
            return packet
        
        packet_ = io.BytesIO(packet) # We do not know yet if this is a minecraft packet
        totaldata = b""

        while True:
            try:
                packet_length, _ = MCProtocolTools.readVarInt(packet_)
                packet_id, = packet_.read(1)
            except: # invalid packet, stop processing
                return packet
            
            packet_identified = False

            for pattern in self.serverbound_patterns:
                if pattern["packet_id"] == packet_id: # subpacket identified
                    try:
                        valid_packet, new_packet = pattern["handler"](packet_length - 1, packet_, packet)
                    except Exception as e:
                        logger.warning(f"[{self.client_name}] Error while handling packet {hex(packet_id)}: {e}")
                        return packet # (probably) invalid subpacket, stop processing
                    
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
        if self.logged_in:
            return packet
        
        packet_ = io.BytesIO(packet) # We do not know yet if this is a minecraft packet
        totaldata = b""

        while True:
            try:
                packet_length, _ = MCProtocolTools.readVarInt(packet_)
                packet_id, = packet_.read(1)
            except: # invalid packet, stop processing
                return packet
            
            packet_identified = False

            for pattern in self.clientbound_patterns:
                if pattern["packet_id"] == packet_id: # subpacket identified
                    try:
                        valid_packet, new_packet = pattern["handler"](packet_length - 1, packet_, packet)
                    except Exception as e:
                        logger.warning(f"[{self.client_name}] Error while handling packet {hex(packet_id)}: {e}")
                        return packet # (probably) invalid subpacket, stop processing
                    
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