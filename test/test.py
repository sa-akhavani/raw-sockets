import unittest
from unittest import TestCase
import httpcode
import utils


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

    def test_spliturl(self):
        url1 = 'https://david.choffnes.com/classes/cs4700fa20/project4.php'
        url2 = 'https://david.choffnes.com/'

        domain1, path1 = utils.spliturl(url1)
        self.assertEqual(domain1, 'david.choffnes.com')
        self.assertEqual(path1, '/classes/cs4700fa20/project4.php')

        domain2, path2 = utils.spliturl(url2)
        self.assertEqual(domain2, 'david.choffnes.com')
        self.assertEqual(path2, '/')

    def test_filenamefromurl(self):
        url1 = 'https://david.choffnes.com/classes/cs4700fa20/project4.php'
        url2 = 'https://david.choffnes.com/'

        self.assertEqual(utils.filenamefromurl(url1), 'project4.php')
        self.assertEqual(utils.filenamefromurl(url2), 'index.html')

    def test_dnslookup(self):
        remote_addr = utils.dnslookup('https://david.choffnes.com/classes/cs4700fa20/project4.php')

    def test_getlocalip(self):
        local_ip = utils.getlocalip()
        self.assertNotEqual(local_ip, '127.0.0.1')
        self.assertNotEqual(local_ip, '127.0.1.1')

    def test_checksum_wikipedia(self):
        bytes = bytearray.fromhex('450000730000400040110000c0a80001c0a800c7')
        print(bytes)
        chksm = utils.checksum16(bytes)
        self.assertEqual(chksm, 0xb861)

    def test_checksum_mathforum(self):
        bytes = bytearray.fromhex('865e ac60 712a 81b5')
        chksm = utils.checksum16(bytes)
        self.assertEqual(chksm, 0xda60)

    def test_checksum_mathforum_padded(self):
        bytes = bytearray.fromhex('865eac60712a81')
        chksm = utils.checksum16(bytes)
        self.assertEqual(chksm, 0xdb15)


if __name__ == '__main__':
    unittest.main()
