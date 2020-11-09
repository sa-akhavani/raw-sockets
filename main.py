import sys
import re
import socket
from httpcode import *

def build_TCP_header():
    return ''

def build_IP_header():
    return ''

def checksum(msg):
    pass

def get_request_header(host, path):
    # Create request string
    request = 'GET ' + path + ' HTTP/1.1\r\n'
    request += 'Host:' + host + '\r\n'
    request += 'Connection: keep-alive\r\n'
    request += '\r\n'
    return request

def handle_send(send_sock):
    packet = ''
    ip_header = build_IP_header()
    tcp_header = build_TCP_header()
    user_data = ''
    packet = ip_header + tcp_header + user_data
    pass

def handle_receive(rcv_sock):
    response = ''
    headers, status, cookies, body = parse_response(response)
    pass

def output_file_name(url):
    file_name = 'index.html'
    if not url[-1] == '/':
        if ('//' in url and url.count('/') > 2) or (('//' not in url and url.count('/') > 0)):
            url_spl = url.split('/')
            file_name = url_spl[-1]
    return file_name

def begin_download(url):
    file_name = output_file_name(url)

    #Create send socket
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    handle_send(send_sock)

    #Create Receive Socket
    rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    handle_receive(rcv_sock)

def main():
    if len(sys.argv) < 2:
        sys.exit("Please provide a URL")    
    begin_download(sys.argv[1])

if __name__ == '__main__':
    main()