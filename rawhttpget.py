import random
import socket
import sys

import httpcode
from ip import IP, deserialize_ip
from tcp import TCP, deserialize_tcp
from utils import spliturl, dnslookup, getlocalip, filenamefromurl, checksum16

SRCPORT = random.randint(1024, 65535)
DSTPORT = 80
MSS = 65535


class Client:
    ssock = None
    rsock = None

    local_ip = None
    remote_ip = None

    def connect(self, local_ip, remote_ip):
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ssock.connect((remote_ip, DSTPORT))

        self.rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.rsock.bind((local_ip, SRCPORT))

        self.local_ip = local_ip
        self.remote_ip = remote_ip

    def send(self, msg):
        self.ssock.sendall(msg)

    def recv(self, debug=False):
        while True:
            data = self.rsock.recv(MSS)
            if debug:
                print(data)

            ip = deserialize_ip(bytearray(data))
            if ip.src == self.remote_ip and ip.dst == self.local_ip:
                if ip.proto == 6:
                    ip.data = deserialize_tcp(ip.data)
                return ip

    def sendip(self, ip, debug=False):
        if debug:
            ip.show()

        self.send(ip.serialize())

    def sendtcp(self, tcp, debug=False):
        tcp.sport = SRCPORT
        tcp.dport = DSTPORT

        # serialize once to get right size
        tcp_slz = tcp.serialize()
        ip = IP(src=self.local_ip, dst=self.remote_ip, proto=6, len=20 + len(tcp_slz))

        # now compute checksum with new IP packet and send it
        tcp.compute_checksum(ip)
        ip.data = tcp.serialize()
        self.sendip(ip, debug)

    def sendrecvtcp(self, tcp, debug=False):
        self.sendtcp(tcp, debug)
        ip = self.recv(debug)
        if debug:
            ip.show()
        return ip


def rawhttpget(url):
    domain, path = spliturl(url)
    remote_addr = dnslookup(url)
    outfn = filenamefromurl(url)
    local_ip = "192.168.198.131"  # TODO get this dynamically via getlocalip()

    getstr = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n'

    c = Client()
    c.connect(local_ip, remote_addr)
    seq = 0  # random.randint(0, 4294967295)
    ack = 0

    # 3 way handshake
    syn = TCP(flags='S',
              seq=seq,
              ack=ack)
    synack = c.sendrecvtcp(syn, True)

    seq = synack.data.ack
    ack = synack.data.seq + 1

    ackpkt = TCP(flags='A',
                 seq=seq,
                 ack=ack,
                 data=bytearray(getstr, encoding='ascii'))
    c.sendrecvtcp(ackpkt, True)  # ignore first packet received
    resp = c.recv(True)
    tcpresp = resp.data

    # for when I inevitably forget this
    # iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    if tcpresp.flags == 'R':
        sys.exit('Received reset after ACK in 3 way handshake. Maybe you forgot to edit iptables?')

    # 3 way handshake complete. open file for writing
    fptr = open(outfn, 'w')

    # now keep receiving packets until the full url has been received
    while True:
        if tcpresp.data is None:
            fptr.close()
            break

        # only update ACK number when the packet is what we expect
        # TODO change this when we support sliding window
        if ack == tcpresp.seq:
            seq = tcpresp.ack
            ack = ack + len(tcpresp.data)

            httpresp = httpcode.HTTPResponse(bytes(tcpresp.data))
            fptr.write(httpresp.body)

        # ack last received packet
        ackpkt = TCP(flags='A',
                     seq=seq,
                     ack=ack)

        resp = c.sendrecvtcp(ackpkt, True)
        tcpresp = resp.data

    finpkt = TCP(flags='F',
                 seq=seq,
                 ack=ack)
    resp = c.sendrecvtcp(finpkt)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('please provide a url')

    rawhttpget(sys.argv[1])
