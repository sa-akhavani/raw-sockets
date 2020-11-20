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

    def testfrag2(self):
        server = Server()
        ntwk = networklayer.NetworkLayer()
        localip = '127.0.0.1'  #utils.getlocalip()
        server.bind((localip, 12345))
        ntwk.connect(localaddrpair=(localip, 54321), remoteaddrpair=(localip, 12345))
        ntwk.settimeout(5)
        server.connect((localip, 54321))

        try:
            frag1 = ip.IP(src=localip, dst=localip, proto=6, len=30, flags='M', frag=0,
                          data=bytearray('aaaaaaaaaa', encoding='utf-8'))
            frag2 = ip.IP(src=localip, dst=localip, proto=6, len=30, flags='', frag=10,
                          data=bytearray('bbbbbbbbbb', encoding='utf-8'))

            x = threading.Thread(target=ntwkthread, args=(ntwk,))
            x.start()

            server.send(frag1)
            server.send(frag2)

            x.join()
        finally:
            pass

        server.shutdown()
        ntwk.shutdown()


if __name__ == '__main__':
    unittest.main()
