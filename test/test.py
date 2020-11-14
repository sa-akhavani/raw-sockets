import unittest
from unittest import TestCase
import httpcode


class Tests(TestCase):
    def test_httprespclass(self):
        slz = b"HTTP/1.1 200 OK\r\nDate: Sat, 14 Nov 2020 16:56:29 GMT\r\nServer: Apache\r\nVary: Accept-Encoding,User-Agent\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n4000\r\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Project 4: CS 5700 Fundamentals of Computer Networking: David Choffnes, Ph.D.</title>\n</html>"
        resp = httpcode.HTTPResponse(slz)

        self.assertEqual(1.1, resp.version)
        self.assertEqual(200, resp.status)
        self.assertEqual(5, len(resp.headers))
        self.assertTrue('Transfer-Encoding' in resp.headers)
        self.assertEqual('chunked', resp.headers['Transfer-Encoding'])
        self.assertTrue(resp.body.startswith('<!DOCTYPE html>'))


if __name__ == '__main__':
    unittest.main()
