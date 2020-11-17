import sys

import utils

"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
Flags:
    bit 0: Reserved; must be zero.[note 1]
    bit 1: Don't Fragment (DF)
    bit 2: More Fragments (MF)
"""

DF = 0x4000
MF = 0x2000


def deserialize_ip(slz):
    """
    Deserializes an IP object from the given bytearray, or throws an exception if serialization failed

    At present, deserialization only supports IPv4 and only allows the underlying protocol to be TCP.
    """
    if len(slz) < 20:
        raise RuntimeError('Buffer length too small: {}'.format(len(slz)))

    pkt = IP()

    version_ihl = slz[0]

    pkt.version = version_ihl >> 4
    if pkt.version != 4:
        raise RuntimeError('Unsupported IP version: {}'.format(pkt.version))

    pkt.ihl = version_ihl & 0x0F
    if pkt.ihl < 5:
        raise RuntimeError('IP header length too small: {}'.format(pkt.ihl))

    pkt.tos = slz[1]

    pkt.len = int.from_bytes(slz[2:4], byteorder='big', signed=False)
    if pkt.len != len(slz):
        raise RuntimeError('IP total length does not match buffer size: {} vs {}'.format(pkt.tos, len(slz)))

    pkt.idnum = int.from_bytes(slz[4:6], byteorder='big', signed=False)

    flags_fragoffset = int.from_bytes(slz[6:8], byteorder='big', signed=False)

    if flags_fragoffset & DF != 0:
        pkt.flags += 'D'

    if flags_fragoffset & MF != 0:
        pkt.flags += 'M'

    pkt.frag = flags_fragoffset & 0x1FFF

    pkt.ttl = slz[8]
    pkt.proto = slz[9]
    if pkt.proto not in [0, 6]:
        raise RuntimeError('IP underlying protocol not supported: {}'.format(pkt.tos))

    pkt.chksum = int.from_bytes(slz[10:12], byteorder='big', signed=False)

    pkt.src = utils.bytearraytoaddr(slz[12:16])
    pkt.dst = utils.bytearraytoaddr(slz[16:20])

    if pkt.ihl > 5:
        pkt.options = slz[20:pkt.ihl*4]

    if pkt.ihl*4 != len(slz):
        pkt.data = slz[pkt.ihl*4:len(slz)]

    return pkt


class IP:
    """Serializer and deserializer class for IP datagrams"""

    def __init__(self, version=4, ihl=5, tos=0x0, len=20,
                 id=1, flags='', frag=0, ttl=64, proto=0,
                 src='127.0.0.1', dst='127.0.0.1',
                 options=None, data=None):
        self.__checkflags(flags)

        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.len = len
        self.idnum = id
        self.flags = flags
        self.frag = frag
        self.chksum = 0x0000
        self.ttl = ttl
        self.proto = proto
        self.src = src
        self.dst = dst
        self.options = options
        self.data = data
        self.compute_checksum()

    def __checkflags(self, flags):
        if flags not in ['', 'D', 'M', 'DM']:
            sys.exit('invalid IP flags field provided: {}'.format(flags))
            
    def compute_checksum(self):
        datagram = self.serialize()
        # zero out checksum before computing
        for i in [10, 11]:
            datagram[i] = 0x00
            
        self.chksum = utils.checksum16(datagram)

    def serialize(self):
        slz = bytearray()

        version_ihl = (self.version << 4) | self.ihl

        flags_fragoffset = self.frag
        self.__checkflags(self.flags)
        for c in range(0, len(self.flags)):
            if self.flags[c] == 'D':
                flags_fragoffset |= DF
            elif self.flags[c] == 'M':
                flags_fragoffset |= MF

        src_bytes = utils.addrtobytearray(self.src)
        dst_bytes = utils.addrtobytearray(self.dst)

        # append all header values to the bytearray
        slz.append(version_ihl)
        slz.append(self.tos)
        slz.extend(utils.serialize16(self.len))
        slz.extend(utils.serialize16(self.idnum))
        slz.extend(utils.serialize16(flags_fragoffset))
        slz.append(self.ttl)
        slz.append(self.proto)
        slz.extend(utils.serialize16(self.chksum))
        slz.extend(src_bytes)
        slz.extend(dst_bytes)

        # append options and data if necessary
        if self.options is not None:
            slz.extend(self.options)

        if self.data is not None:
            slz.extend(self.data)

        return slz
