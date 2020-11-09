import sys
import socket
import re

HTTP_STATUS_CODES = {
    200: '200 OK'
}

# Extract body from the server response string
def extract_response_body(response):
    lines = response.splitlines()
    
    for line in lines:
        if 'Content-Type:' in line:
            body_start_index = lines.index(line) + 1

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
