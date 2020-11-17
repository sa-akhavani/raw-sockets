import unittest
from unittest import TestCase
import ip
import scapy.layers.inet as scapyip


class IPTest(TestCase):
    def assertoursequalsscapys(self, pkt, scapypkt):
        self.assertEqual(pkt.version, scapypkt[scapyip.IP].version)
        self.assertEqual(pkt.ihl, scapypkt[scapyip.IP].ihl)
        self.assertEqual(pkt.tos, scapypkt[scapyip.IP].tos)
        self.assertEqual(pkt.len, scapypkt[scapyip.IP].len)
        self.assertEqual(pkt.idnum, scapypkt[scapyip.IP].id)
        self.assertEqual(pkt.flags, scapypkt[scapyip.IP].flags)
        self.assertEqual(pkt.frag, scapypkt[scapyip.IP].frag)
        self.assertEqual(pkt.chksum, scapypkt[scapyip.IP].chksum)
        self.assertEqual(pkt.ttl, scapypkt[scapyip.IP].ttl)
        self.assertEqual(pkt.proto, scapypkt[scapyip.IP].proto)
        self.assertEqual(pkt.src, scapypkt[scapyip.IP].src)
        self.assertEqual(pkt.dst, scapypkt[scapyip.IP].dst)
        self.assertEqual(pkt.options, scapypkt[scapyip.IP].options)
        self.assertEqual(pkt.data, scapypkt[scapyip.IP].data)

    def test_ipchecksum(self):
        pkt = ip.IP()
        self.assertEqual(0x7ce7, pkt.chksum)

    def test_serialize_default(self):
        pkt = ip.IP()
        slz = pkt.serialize()
        self.assertEqual(20, len(slz))
        self.assertEqual(bytearray(bytes(scapyip.IP())), slz)

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


if __name__ == '__main__':
    unittest.main()
