import socket
import sys
import threading
import unittest

sys.path.append('../')
import utils
import ip
import networklayer


class Server:
    """Simple server that allows sending and receiving packets"""
    ssock = None
    rsock = None

    def bind(self, localaddrpair):
        self.rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rsock.bind(localaddrpair)

    def connect(self, remoteaddrpair):
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ssock.connect(remoteaddrpair)

    def shutdown(self):
        self.rsock.close()
        self.ssock.close()

    def send(self, pkt):
        slz = pkt.serialize()
        self.ssock.sendall(slz)

    def recv(self):
        return self.rsock.recv(65535)


def ntwkthread(ntwk):
    print('starting ntwkthread')
    ippkt = ntwk.recv()
    print('received')
    ippkt.show()


class NetworkTest(unittest.TestCase):
    def DISABLED_testtimeout(self):
        ntwk = networklayer.NetworkLayer()
        localip = utils.getlocalip()
        ntwk.connect((localip, 12345), ('204.44.192.60', 80))
        ntwk.settimeout(1)
        ntwk.recv()

    def testfraginorder(self):
        ntwk = networklayer.NetworkLayer()
        localip = '127.0.0.1'  #utils.getlocalip()

        frag1 = ip.IP(src=localip, dst=localip, proto=6, len=28, flags='M', frag=0,
                      data=bytearray('aaaaaaaa', encoding='utf-8'))
        frag2 = ip.IP(src=localip, dst=localip, proto=6, len=28, flags='', frag=1,
                      data=bytearray('bbbbbbbb', encoding='utf-8'))

        self.assertIsNone(ntwk.handle_fragment(frag1))
        reass = ntwk.handle_fragment(frag2)
        self.assertIsNotNone(reass)
        self.assertEqual(reass.data, bytearray('aaaaaaaabbbbbbbb', encoding='utf-8'))

    def testfragoutoforder(self):
        ntwk = networklayer.NetworkLayer()
        localip = '127.0.0.1'  #utils.getlocalip()

        frag1 = ip.IP(src=localip, dst=localip, proto=6, len=28, flags='M', frag=0,
                      data=bytearray('aaaaaaaa', encoding='utf-8'))
        frag2 = ip.IP(src=localip, dst=localip, proto=6, len=28, flags='', frag=1,
                      data=bytearray('bbbbbbbb', encoding='utf-8'))

        self.assertIsNone(ntwk.handle_fragment(frag2))
        reass = ntwk.handle_fragment(frag1)
        self.assertIsNotNone(reass)
        self.assertEqual(reass.data, bytearray('aaaaaaaabbbbbbbb', encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
