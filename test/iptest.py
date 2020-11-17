import unittest
from unittest import TestCase
import ip
import scapy.layers.inet as scapyip

import utils


class IPTest(TestCase):

    def test_ipchecksum_default(self):
        pkt = ip.IP()
        self.assertEqual(0x7ce7, pkt.chksum)

    def test_ipchecksum_specific(self):
        pkt = ip.IP(version=4, ihl=5, tos=0, len=40, id=1, flags='', frag=0, ttl=64, proto=6,
                    src='192.168.198.131', dst='204.44.192.60')
        self.assertEqual(0x673a, pkt.chksum)

    def test_ipchecksum_specific_withpayload(self):
        pkt = ip.IP(version=4, ihl=5, tos=0, len=40, id=1, flags='', frag=0, ttl=64, proto=6,
                    src='192.168.198.131', dst='204.44.192.60',
                    data=bytearray(b'\x82(\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x00\x00\x00\x00'))
        self.assertEqual(0x673a, pkt.chksum)

    def serializetest_givenflag(self, flag, scapyflags):
        pkt = ip.IP(flags=flag)
        scapypkt = scapyip.IP(flags=scapyflags)

        self.assertEqual(20, len(pkt.serialize()))
        self.assertEqual(bytes(pkt.serialize()).hex(), bytes(scapypkt).hex())

    def test_serialize_default(self):
        self.serializetest_givenflag('', '')

    def test_serialize_flags(self):
        ourflags = ['D', 'M', 'DM']
        scapyflags = ['DF', 'MF', 'MF+DF']

        for i in range(3):
            self.serializetest_givenflag(ourflags[i], scapyflags[i])

    def test_deserialize_default(self):
        scapypkt = scapyip.IP()
        slz = bytearray(bytes(scapypkt))
        pkt = ip.deserialize_ip(slz)

        self.assertEqual(pkt.version, 4)
        self.assertEqual(pkt.ihl, 5)
        self.assertEqual(pkt.tos, 0)
        self.assertEqual(pkt.len, 20)
        self.assertEqual(pkt.idnum, 1)
        self.assertEqual(pkt.flags, '')
        self.assertEqual(pkt.frag, 0)
        self.assertEqual(pkt.chksum, 0x7ce7)
        self.assertEqual(pkt.ttl, 64)
        self.assertEqual(pkt.proto, 0)
        self.assertEqual(pkt.src, '127.0.0.1')
        self.assertEqual(pkt.dst, '127.0.0.1')
        self.assertEqual(pkt.options, None)
        self.assertEqual(pkt.data, None)

    def test_pseudoheader(self):
        pkt = ip.IP(version=4, ihl=5, tos=0, len=40, id=1, flags='', frag=0, ttl=64, proto=6,
                    src='192.168.198.131', dst='204.44.192.60',
                    data=bytearray(b'\x82(\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x00\x00\x00\x00'))
        pseudo = utils.getpseudoheader(pkt)

        self.assertEqual(12, len(pseudo))
        self.assertEqual(pseudo, bytearray(b'\xc0\xa8\xc6\x83\xcc,\xc0<\x00\x06\x00\x14'))


if __name__ == '__main__':
    unittest.main()
