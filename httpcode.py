import sys
from enum import Enum

HTTP_STATUS_CODES = {
    200: '200 OK'
}


class ParseState(Enum):
    RDNEW = 1
    RDSIZE = 2
    RDCHUNK = 3


class HTTPResponse:
    # class variable
    parsestate = ParseState.RDNEW

    # instance variables
    version = None
    status = None
    headers = None
    body = ''
    ischunked = False

    debug = False

    def __extractversionstatus(self, line):
        """Extracts the HTTP version and status code"""
        spl = line.split(' ')
        self.version = float(spl[0].split('/')[1])
        self.status = int(spl[1])

    def __extractheaders(self, lines):
        self.headers = dict()
        bodystart = 1

        for line in lines:
            bodystart += 1

            if line == '':
                break

            spl = line.split(': ')
            self.headers[spl[0]] = spl[1]

        # handle chunked encoding
        if 'Transfer-Encoding' in self.headers and self.headers['Transfer-Encoding'] == 'chunked':
            self.ischunked = True

        return bodystart

    def __extractbody(self, lines):
        if len(lines) == 0:
            self.body = ''
            return

        self.body = lines[0]

        for i in range(1, len(lines)):
            line = lines[i]

            self.body += '\r\n'
            self.body += line

    def __bodyfsm(self, lines):
        for i in range(len(lines)):
            if HTTPResponse.parsestate == ParseState.RDSIZE:
                if int(lines[i], 16) == 0:
                    # terminating chunk, we're done
                    HTTPResponse.parsestate = ParseState.RDNEW
                    return

                # otherwise, skip the size, start reading the chunk
                HTTPResponse.parsestate = ParseState.RDCHUNK

            elif HTTPResponse.parsestate == ParseState.RDCHUNK:
                self.body += lines[i]

                # if chunk was followed by a CRLF and isn't the last line in the body, then it's followed by a size
                # if it is the last line in the body, then there will be another
                if i != len(lines) - 1:
                    HTTPResponse.parsestate = ParseState.RDSIZE

    def __init__(self, slz):
        """
        slz (bytes) - HTTP response extracted from a TCP packet
        """
        slz = slz.decode('utf-8', 'replace')  # 'replace' allows us to decode bytes 0x80-0xff
        lines = slz.split('\r\n')

        if HTTPResponse.parsestate == ParseState.RDNEW:
            # extract code from first line
            self.__extractversionstatus(lines[0])

            # extract headers then the body
            bodystart = self.__extractheaders(lines[1:])

            if not self.ischunked:
                self.__extractbody(lines[bodystart:])
            else:
                HTTPResponse.parsestate = ParseState.RDSIZE
                self.__bodyfsm(lines[bodystart:])
        else:
            self.__bodyfsm(lines)


# Extract body from the server response string
def extract_response_body(response):
    lines = response.splitlines()

    body_start_index = None
    for line in lines:
        if 'Content-Type:' in line:
            body_start_index = lines.index(line) + 1

    if body_start_index is None:
        sys.exit('could not determine http body start index')

    body = ''
    for idx in range(body_start_index, len(lines)):
        body += str(lines[idx])

    return body


# Extract headers from the server response string
def extract_headers(response):
    headers = []
    lines = response.splitlines()
    
    for line in lines:
        headers.append(line)
        if 'Content-Type:' in line:
            break

    return headers


# Extract cookies from the server response string
def extract_cookies(headers):
    out = dict()
    for header in headers:
        if 'Set-Cookie: ' in header:
            header = header[len('Set-Cookie: '):]
            spliteq = header.split('=')
            splitsemi = spliteq[1].split(';')
            out[spliteq[0]] = splitsemi[0]

    return out

# Extrac
# t http status code from the server response string
def extract_http_status_code(headers):
    if HTTP_STATUS_CODES.get(200) in headers[0]:
        return 200
    else:
        print('Unknown Status Code Received: ', headers[0])
        return 500


# High level function for parsing the received response from the server
def parse_response(response):
    headers = extract_headers(response)
    status = extract_http_status_code(headers)
    cookies = extract_cookies(headers)
    body = None

    if status == 200:
        body = extract_response_body(response)

    return headers, status, cookies, body
