from cc1101 import check_crc
from scapy.packet import Packet
from scapy.fields import *


POWER_DBM_MAP = {
    0: -10,
    1: 14,  # could be 14 or anything besides -10, 8, 2
    2: 8,
    3: 2,
}


class PowerGPacket(Packet):
    name = "PowerGPacket"

    fields_desc = [
        LenField("length", None, fmt='B'),

        ## set to 0xFF for broadcast
        XByteField("dst_addr", 0x01),
        XByteField("src_addr", 0xfe),
        ## set to 0xFF for broadcast
        ## if dst matches some special addr it's set to 0xFD, else it's set to the special addr (default special addr is 1)
        ## "special addr" is maybe the main panel modem addr, or a relay addr?
        XByteField("addr_related", 0xfd),

        # byte 4
        ## just cleared to 0
        XBitField("byte4_bit7", 0, 1),
        ## increments for each queued TX packet, rolls over at 8. used to detect & discard duplicate packets
        XBitField("dedupe_counter", 0, 3),
        ## grp0 counts to 15, grp0 prep echoes back count in TX responses
        ## grp1 sets to 0
        ## grp2 sets to 1
        ## grp3 doesn't set it
        XBitField("notification_period_maybe", 0, 4),

        # byte 5
        BitEnumField("tx_power", 1, 2, POWER_DBM_MAP),
        XBitField("byte5_bit5", 0, 1),
        XBitField("byte5_bit4", 0, 1),
        XBitField("nonce_mode", 0, 2),
        XBitField("byte5_bit1", 0, 1),
        XBitField("no_time_info", 1, 1),

        # byte 6
        XBitField("byte6_bit7", 0, 1),
        XBitField("byte6_bit6", 0, 1),
        XBitField("byte6_bit5_4", 0, 2),
        XBitField("byte6_bit3", 0, 1),
        XBitField("byte6_bit2_0", 0, 3),

        XByteField("msg_type", 0x80),

        XStrFixedLenField("keystream_head", b'\xff\xff', 2),

        #XStrLenField("load", "", lambda pkt: pkt.length - 10),
        TrailerField(XShortField("crc", None)),
    ]

    def get_payload(self):
        # remove null byte at the end of RF packets
        if not self.check_crc():
            return self.load

        if self.load[-1:] != b'\x00':
            raise Exception("doesn't end with 00")

        return self.load[:-1]

    def get_timestamp(self):
        if self.no_time_info:
            return None

        timestamp_bytes = self.get_payload()[-4:]
        timestamp = int.from_bytes(timestamp_bytes, "little")

        return timestamp

    def check_crc(self):
        return check_crc(bytes(self))
