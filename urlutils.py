import socket
import sys
from urllib.parse import urlparse

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

    if path == '' or path[-1] == '/':
        path = '/index.html'

    return domain, path


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('please provide a url')

    url = sys.argv[1]
    domain, path = spliturl(url)

    print('domain:', domain)
    print('path:', path)

    addr = socket.gethostbyname(domain)
    print('address of host:', addr)

    hostname = socket.getfqdn()
    local_ip = socket.gethostbyname(hostname)
    print('local hostname:', hostname)
    print('local IP:', local_ip)
