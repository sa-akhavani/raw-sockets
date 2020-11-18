import random
import socket
import sys

import scapy
from scapy.layers.http import HTTP
from scapy.layers.inet import TCP

import httpcode
from ip import IP, deserialize_ip
from tcp import deserialize_tcp
from utils import spliturl, dnslookup, getlocalip, filenamefromurl, checksum16

'''
https://stackoverflow.com/questions/4750793/python-scapy-or-the-like-how-can-i-create-an-http-get-request-at-the-packet-leve
https://scapy.readthedocs.io/en/latest/layers/http.html

syn = IP(dst='www.google.com') / TCP(dport=80, flags='S')
syn_ack = sr1(syn)
getStr = 'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'
request = IP(dst='www.google.com') / 
          TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / 
          getStr
reply = sr1(request)
'''

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
            ip.show2()
            #scapy.layers.inet.IP(bytes(ip.serialize())).show2()

        #self.send(ip.serialize())
        self.send(bytes(ip))

    def sendtcp(self, tcp, debug=False):
        tcp[TCP].sport = SRCPORT
        tcp[TCP].dport = DSTPORT
        tcp_slz = bytearray(bytes(tcp))

        #ip = IP(src=self.local_ip, dst=self.remote_ip, proto=6, data=tcp_slz, len=20 + len(tcp_slz))
        ip = scapy.layers.inet.IP(src=self.local_ip, dst=self.remote_ip) / tcp
        self.sendip(ip, debug)

    def sendrecvtcp(self, tcp, debug=False):
        self.sendtcp(tcp, debug)
        ip = self.recv()
        if debug:
            ip.show()
        return ip


def gethttpmagicnumber(httpload):
    spl = httpload.split(b'\r\n')
    return spl[0]


def rawhttpget(url):
    if ('http://' not in url):
        url = 'http://' + url
    domain, path = spliturl(url)
    remote_addr = dnslookup(url)
    outfn = filenamefromurl(url)
    local_ip = getlocalip()
    getstr = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n'

    c = Client()
    c.connect(local_ip, remote_addr)
    seq = 0  # random.randint(0, 4294967295)
    ack = 0

    # 3 way handshake
    syn = TCP(flags='S',
              seq=seq,
              ack=ack)
    synack = c.sendrecvtcp(syn)

    seq = synack.data.ack
    ack = synack.data.seq + 1

    ackpkt = TCP(flags='A',
                 seq=seq,
                 ack=ack) / getstr
    c.sendrecvtcp(ackpkt)  # ignore first packet received
    resp = c.recv()

    fptr = open(outfn, 'w')

    # for when I inevitably forget this
    # iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    if resp.data.flags == 'R':
        sys.exit('Received reset after ACK in 3 way handshake. Maybe you forgot to edit iptables?')

    # now keep receiving packets until the full url has been received
    while True:
        #if not resp.data.haslayer(HTTP):
        if resp.data.data is None:
            fptr.close()
            break

        # only update ACK number when the packet is what we expect
        # TODO change this when we support sliding window
        if ack == resp.data.seq:
            seq = resp.data.ack
            ack = ack + len(resp.data.data)

            nonscapyresp = httpcode.HTTPResponse(bytes(resp.data.data))
            fptr.write(nonscapyresp.body)

        # ack last received packet
        ackpkt = TCP(flags='A',
                     seq=seq,
                     ack=ack)

        resp = c.sendrecvtcp(ackpkt)

    finpkt = TCP(flags='F',
                 seq=seq,
                 ack=ack)
    resp = c.sendrecvtcp(finpkt)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('please provide a url')

    rawhttpget(sys.argv[1])
