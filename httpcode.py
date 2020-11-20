import sys
from enum import Enum

HTTP_STATUS_CODES = {
    200: '200 OK'
}


class ParseState(Enum):
    RDNEW = 1  # reading a brand new http packet with headers
    RDSIZE = 2  # reading the size from a chunked body
    RDCHUNK = 3  # reading a chunk from a chunked body
    RDSTREAM = 4  # reading the entire body as part of a larger message


TRANSFER_ENCODING = 'Transfer-Encoding'
CONTENT_TYPE = 'Content-Type'
CONTENT_LENGTH = 'Content-Length'
ACCEPT_RANGES = 'Accept-Ranges'


class HTTPResponse:
    # class variables
    parsestate = ParseState.RDNEW
    total_length = 0
    recvd_length = 0

    # instance variables
    version = None
    status = None
    headers = None
    body = ''
    ischunked = False
    isbytes = False

    debug = False

    def __extractversionstatus(self, line):
        """Extracts the HTTP version and status code"""
        spl = line.split(' ')
        self.version = float(spl[0].split('/')[1])
        self.status = int(spl[1])

    def extractheaders(self, lines):
        self.headers = dict()
        bodystartline = 1
        bodystartbyte = len(lines[0]) + 2  # +2 for \r\n

        for line in lines[1:]:
            bodystartline += 1
            bodystartbyte += len(line) + 2

            if line == '':
                break

            spl = line.split(': ')
            self.headers[spl[0]] = spl[1]

        # handle chunked encoding
        if TRANSFER_ENCODING in self.headers and self.headers[TRANSFER_ENCODING] == 'chunked':
            self.ischunked = True

        return bodystartline, bodystartbyte

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

    def __handle_bytestream(self, slz):
        """
        Handles an HTTP response that is a part of a byte stream split across multiple messages

        slz (bytearray) - body of the HTTP response
        """

        # just write body in raw bytes form.
        self.body = slz
        HTTPResponse.recvd_length += len(self.body)

        if HTTPResponse.recvd_length == HTTPResponse.total_length:
            HTTPResponse.parsestate = ParseState.RDNEW
            HTTPResponse.total_length = 0
            HTTPResponse.recvd_length = 0
            self.isbytes = False

    def __init__(self, slz):
        """
        slz (bytes) - HTTP response extracted from a TCP packet
        """
        slzstr = slz.decode('utf-8', 'replace')  # 'replace' allows us to decode bytes 0x80-0xff
        lines = slzstr.split('\r\n')

        if HTTPResponse.parsestate == ParseState.RDNEW:
            # extract code from first line
            self.__extractversionstatus(lines[0])

            # extract headers then the body
            bodystartline, bodystartbyte = self.extractheaders(lines)

            if self.ischunked:
                HTTPResponse.parsestate = ParseState.RDSIZE
                self.__bodyfsm(lines[bodystartline:])

            elif ACCEPT_RANGES in self.headers and self.headers[ACCEPT_RANGES] == 'bytes' and CONTENT_LENGTH in self.headers:
                self.isbytes = True
                HTTPResponse.total_length = int(self.headers[CONTENT_LENGTH])
                HTTPResponse.parsestate = ParseState.RDSTREAM

                self.__handle_bytestream(slz[bodystartbyte:])

            else:
                self.body = slzstr[bodystartbyte:]
        elif HTTPResponse.parsestate == ParseState.RDSTREAM:
            self.__handle_bytestream(slz)
        else:
            self.__bodyfsm(lines)


# Extract body from the server response string
def extract_response_body(response):
    lines = response.splitlines()

    body_start_index = None
    for line in lines:
        if CONTENT_TYPE in line:
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


# Extract http status code from the server response string
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
