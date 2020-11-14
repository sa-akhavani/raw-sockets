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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('please provide a url')

    url = sys.argv[1]

    domain, path = spliturl(url)
    print('domain:', domain)
    print('path:', path)
    print('filename from full url:', filenamefromurl(url))
    print('filename from path:', filenamefromurl(path))

    remote_addr = dnslookup(url)
    print('address of remote server:', remote_addr)

    local_ip = getlocalip()
    print('local IP addr:', local_ip)
