import sys
import unittest

sys.path.append('../')
import networklayer
import transportlayer


class NetworkTest(unittest.TestCase):
    def testtransporttimeout(self):
        ntwk = networklayer.NetworkLayer()
        ntwk.connect(('127.0.0.1', 12345), ('204.44.192.60', 80))

        trans = transportlayer.TransportLayer(ntwk=ntwk, sport=12345, dport=80)
        trans.timeout = 1
        ntwk.settimeout(3)
        trans.recv()


if __name__ == '__main__':
    unittest.main()
