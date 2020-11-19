import random
import sys

import httpcode
import networklayer
import transportlayer
from utils import spliturl, dnslookup, getlocalip, filenamefromurl

SRCPORT = random.randint(1024, 65535)
DSTPORT = 80
DEBUG = False


class Socket:
    """Network interface object that supports sending and receiving strings over a TCP connection"""
    ntwk = None
    trans = None

    def connect(self, localaddrpair, remoteaddrpair):
        """
        Binds to the given local IP address and port and connects to the given remote IP address and port

        localaddrpair - 2-tuple with format (ip_address as a string, port as an int)
        remoteaddrpair - same as localaddrpair
        """
        self.ntwk = networklayer.NetworkLayer()
        self.ntwk.connect(localaddrpair, remoteaddrpair)
        self.trans = transportlayer.TransportLayer(self.ntwk, SRCPORT, DSTPORT, DEBUG)

    def shutdown(self):
        """Terminates the connection with the remote server"""
        self.trans.shutdown()

    def send(self, data):
        """
        Sends the given data over the network

        data (str or bytearray) - data to be sent
        """
        if isinstance(data, str):
            data = bytearray(data, encoding='ascii')

        self.trans.send(data)

    def recv(self):
        """
        Receives a bytearray message from the remote server

        return (bytearray) the data received from the server
        """
        return self.trans.recv()


def rawhttpget(url):
    """
    Retrieves the file at the given url over an HTTP connection using raw sockets and writes it to a file

    url (str) - url of the page to be retrieved
    """
    # add http if user did not supply
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    # get filename to write to, remote IPaddress, and our local IP address
    domain, path = spliturl(url)
    outfn = filenamefromurl(url)
    remote_addr = dnslookup(url)
    local_ip = getlocalip()

    # connect to the remote server
    s = Socket()
    s.connect((local_ip, SRCPORT), (remote_addr, DSTPORT))

    # send get request
    getstr = 'GET ' + path + ' HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n'
    s.send(getstr)

    fptr = open(outfn, 'w')

    # in a loop, read from the server, then write the HTTP response body to the file
    while True:
        data = s.recv()

        if data is None:
            fptr.close()
            break

        httpresp = httpcode.HTTPResponse(bytes(data))
        fptr.write(httpresp.body)

    # gracefully shutdown connection
    s.shutdown()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('please provide a url')

    rawhttpget(sys.argv[1])
