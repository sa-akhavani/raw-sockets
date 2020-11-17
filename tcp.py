import utils

"""
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
   ################ Pseudo header used in checksum computation
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Fixed     |    Protocol   |      TCP Segment Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

URG = 0x0020
ACK = 0x0010
PSH = 0x0008
RST = 0x0004
SYN = 0x0002
FIN = 0x0001

flagvals = [URG, ACK, PSH, RST, SYN, FIN]
flagstrs = ['U', 'A', 'P', 'R', 'S', 'F']


def deserialize_tcp(slz):
    """
    Deserializes an TCP object from the given bytearray, or throws an exception if serialization failed
    """
    if len(slz) < 20:
        raise RuntimeError('TCP buffer length too small: {}'.format(len(slz)))

    pkt = TCP()

    pkt.sport = utils.deserializeint(slz[0:2])
    pkt.dport = utils.deserializeint(slz[2:4])
    pkt.seq = utils.deserializeint(slz[4:8])
    pkt.ack = utils.deserializeint(slz[8:12])

    offset_flags = utils.deserializeint(slz[12:14])
    pkt.dataofs = offset_flags >> 12

    for i in range(len(flagvals)):
        if offset_flags & flagvals[i] != 0:
            pkt.flags += flagstrs[i]

    pkt.window = utils.deserializeint(slz[14:16])
    pkt.chksum = utils.deserializeint(slz[16:18])
    pkt.urgptr = utils.deserializeint(slz[18:20])

    if pkt.dataofs > 5:
        pkt.options = slz[20:pkt.dataofs*4]

    if len(slz) > pkt.dataofs*4:
        pkt.data = slz[pkt.dataofs*4:len(slz)]

    return pkt


class TCP:
    """Serializer and deserializer class for IP datagrams"""

    def __init__(self, sport=20, dport=80, seq=0, ack=0,
                 dataofs=5, flags='', window=8192,
                 urgptr=0, options=None, data=None):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.dataofs = dataofs
        self.flags = flags
        self.window = window
        self.chksum = 0x0000
        self.urgptr = urgptr
        self.options = options
        self.data = data

    def show(self):
        print('###[ TCP ]### ')
        print('  sport: {}'.format(self.sport))
        print('  dport: {}'.format(self.dport))
        print('  seq: {}'.format(self.seq))
        print('  ack: {}'.format(self.ack))
        print('  dataofs: {}'.format(self.dataofs))
        print('  flags: {}'.format(self.flags))
        print('  window: {}'.format(self.window))
        print('  chksum: {}'.format(self.chksum))
        print('  urgptr: {}'.format(self.urgptr))
        print('  options: {}'.format(self.options))
        print('  data: {}'.format(self.data))

    def __checkflags(self, flags):
        errstr = 'invalid TCP flags field provided: {}'.format(flags)

        if len(flags) > 6:
            raise RuntimeError(errstr)

        for c in range(len(flags)):
            if flags[c] not in ['U', 'A', 'P', 'R', 'S', 'F']:
                raise RuntimeError(errstr)

    def compute_checksum(self, ip):
        ip_pseudohdr = utils.getpseudoheader(ip)
        tcp_slz = self.serialize()
        ip_pseudohdr.extend(tcp_slz)
        self.chksum = utils.checksum16(ip_pseudohdr)

    def serialize(self):
        """Serializes this TCP packet into a bytearray that can be sent over a raw socket"""
        slz = bytearray()

        slz.extend(utils.serialize16(self.sport))
        slz.extend(utils.serialize16(self.dport))
        slz.extend(utils.serialize32(self.seq))
        slz.extend(utils.serialize32(self.ack))

        # Build 16-bit value for data offset and flags
        offset_flags = self.dataofs << 12
        self.__checkflags(self.flags)

        for c in range(len(self.flags)):
            idx = flagstrs.index(self.flags[c])
            offset_flags |= flagvals[idx]

        slz.extend(utils.serialize16(offset_flags))
        slz.extend(utils.serialize16(self.window))
        slz.extend(utils.serialize16(self.chksum))
        slz.extend(utils.serialize16(self.urgptr))

        # append options and data if necessary
        if self.options is not None:
            slz.extend(self.options)

        if self.data is not None:
            slz.extend(self.data)

        return slz
