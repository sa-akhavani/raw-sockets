import sys
import unittest

sys.path.append('../')
import networklayer


class NetworkTest(unittest.TestCase):
    def testtimeout(self):
        ntwk = networklayer.NetworkLayer()
        ntwk.connect(('127.0.0.1', 12345), ('204.44.192.60', 80))
        ntwk.settimeout(1)
        ntwk.recv()


if __name__ == '__main__':
    unittest.main()
