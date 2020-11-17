import socket
import sys
from urllib.parse import urlparse
import urllib.request

'''
Your program does not need to support HTTPS. 
Your program does not need to follow redirects, or handle HTTP status codes other than 200. 
In the case of a non-200 status code, print an error to the console and close the program. 
Your program does not need to follow links or otherwise parse downloaded HTML. 

You may use existing OS APIs to query for the IP of the remote HTTP server as well as the IP of the source machine. 
Be careful that you select the correct IP address of the local machine. Do not bind to localhost (127.0.0.1)!
'''


def spliturl(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    return domain, path


def filenamefromurl(url):
    if url == '' or url[-1] == '/':
        return 'index.html'

    spl = url.split('/')
    return spl[-1]


def dnslookup(url):
    domain, _ = spliturl(url)
    return socket.gethostbyname(domain)


def getlocalip():
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    return external_ip


def addrtobytearray(addr):
    """Converts the given IP address (given as a dot-separated string) into a bytearray of length 4"""
    spl = addr.split('.')
    if len(spl) != 4:
        raise RuntimeError('invalid IP address: {}'.format(addr))

    out = bytearray()
    for part in spl:
        out.append(int(part))

    return out


def bytearraytoaddr(slz):
    """Converts the given bytearray to an IP address as a dot-separated string"""
    if len(slz) != 4:
        raise RuntimeError('Array wrong length to be an IPv4 address')

    out = str(slz[0])

    for i in range(1, 4):
        out += '.'
        out += str(slz[i])

    return out


def serialize16(value):
    """Returns the given 16-bit value as a bytearray of length 2"""
    return bytearray(value.to_bytes(2, byteorder='big', signed=False))


def checksum16(bytevec):
    """
    Computer a checksum for the given byte array. The checksum is the one's complement of the one's complement addition
    of all 16-bit words in the given bytearray. If the given array has an odd number of octets, then the array is
    right-padded with 0x00.
    """
    # check if len(bytevec) is multiple of 16. pad with zeroes if not
    if len(bytevec) % 2 != 0:
        bytevec.append(0x00)

    # add up all 16-bit numbers in bytevec
    sum = int.from_bytes(bytevec[0:2], byteorder='big')

    for idx in range(2, len(bytevec) - 1, 2):
        nextoctet = int.from_bytes(bytevec[idx:idx+2], byteorder='big')
        sum += nextoctet

        # check carry bits
        if sum > 0xffff:
            sum = sum - 0x10000 + 1

    # flip all bits in the sum and return it
    sum_bytes = serialize16(sum)
    sum_bytes[0] ^= 0xff
    sum_bytes[1] ^= 0xff
    invertedsum = int.from_bytes(sum_bytes, byteorder='big', signed=False)

    return invertedsum
