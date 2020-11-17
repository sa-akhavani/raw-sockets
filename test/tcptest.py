import unittest
import tcp
import ip
import scapy.layers.inet as scapytcp

import utils


class TCPTest(unittest.TestCase):
    def test_tcpchecksum_default(self):
        pkt = tcp.TCP()
        pkt.compute_checksum(ip.IP(proto=6, len=40))
        self.assertEqual(0x917e, pkt.chksum)

    def serializetest_givenflag(self, flag):
        pkt = tcp.TCP(flags=flag)
        scapypkt = scapytcp.TCP(flags=flag)

        self.assertEqual(20, len(pkt.serialize()))
        self.assertEqual(bytes(pkt.serialize()).hex(), bytes(scapypkt).hex())

    def test_serialize_default(self):
        self.serializetest_givenflag('')

    def test_serialize_withflags(self):
        for flag in ['U', 'A', 'P', 'R', 'S', 'F']:
            self.serializetest_givenflag(flag)

    def test_serialize_seq(self):
        pkt = tcp.TCP(seq=123456789)
        scapypkt = scapytcp.TCP(flags='', seq=123456789)

        self.assertEqual(20, len(pkt.serialize()))
        self.assertEqual(bytes(pkt.serialize()).hex(), bytes(scapypkt).hex())

    def test_serialize_ack(self):
        pkt = tcp.TCP(ack=987654321)
        scapypkt = scapytcp.TCP(flags='', ack=987654321)

        self.assertEqual(20, len(pkt.serialize()))
        self.assertEqual(bytes(pkt.serialize()).hex(), bytes(scapypkt).hex())

    def test_serialize_data(self):
        pkt = tcp.TCP(data=bytearray('GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n', encoding='ascii'))
        scapypkt = scapytcp.TCP(flags='') / 'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'

        self.assertEqual(60, len(pkt.serialize()))
        self.assertEqual(bytes(pkt.serialize()).hex(), bytes(scapypkt).hex())

    def test_deserialize_default(self):
        scapypkt = scapytcp.TCP(flags='')
        slz = bytearray(bytes(scapypkt))
        pkt = tcp.deserialize_tcp(slz)

        self.assertEqual(pkt.sport, 20)
        self.assertEqual(pkt.dport, 80)
        self.assertEqual(pkt.seq, 0)
        self.assertEqual(pkt.ack, 0)
        self.assertEqual(pkt.dataofs, 5)
        self.assertEqual(pkt.flags, '')
        self.assertEqual(pkt.window, 8192)
        self.assertEqual(pkt.urgptr, 0)
        self.assertEqual(pkt.options, None)
        self.assertEqual(pkt.data, None)

    def test_deserialize_specific(self):
        recvdbytes = b'E\x00\x16\xf8\xdf\xd5\x00\x00\x80\x060\x95\xcc,\xc0<\xc0\xa8\xc6\x83\x00P\xec\xfb{\x91>\xa0\x00\x00\x00LP\x18\xfa\xf0*\x80\x00\x00e on a stock Ubuntu Linux 20.04 machine,\nso keep that in mind when developing your code and setting up your VM. <b>Do not develop your program\non Windows or OSX</b>: the APIs for raw sockets on those systems are incompatible with Linux, and thus\nyour code will not work when we grade it.\n</p><p>\nFor most of you, the VM option will probably be easiest. There are many\n<a href="https://ubuntu.tutorials24x7.com/blog/how-to-install-ubuntu-on-windows-using-vmware-workstation-player">tutorials</a>\non how to do this.\nIf you use Windows, you will need a (free) copy of VMWare Player, as well as an ISO of Ubuntu. Once\nyou have your VM set up, you will need to install development tools. Exactly what you need will depend\non what language you want to program in. There are ample instructions online explaining how to install\ngcc, Java, and Python-dev onto Ubuntu.\n</p><p>\n<h2>Modifying IP Tables</h2>\nRegardless of whether you are developing on your own copy of Linux or in a VM, you will need to make\none change to <i>iptables</i> in order to complete this assignment. You must set a rule in <i>iptables</i>\nthat drops outgoing TCP RST packets, using the following command:\n<pre>% iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP</pre>\nTo understand why you need this rule, think about how the kernel behaves when it receives unsolicited TCP\npackets. If your computer receives a TCP packet, and there are no open ports waiting to receive that packet,\nthe kernel generates a TCP RST packet to let the sender know that the packet is invalid. However, in your\ncase, your program is using a raw socket, and thus the kernel has no idea what TCP port you are using. So,\nthe kernel will erroneously respond to packets destined for your program with TCP RSTs. You don\'t want\nthe kernel to kill your remote connections, and thus you need to instruct the kernel to drop outgoing\nTCP RST packets. You will need to recreate this rule each time your reboot your machine/VM.\n</\r\n131f\r\np><p>\n<h2>Debugging</h2>\nDebugging raw socket code can be very challenging. You will need to get comfortable with \n<a href="http://www.wireshark.org/">Wireshark</a>\nin order to debug your code. Wireshark is a packet sniffer, and can parse all of the relevent fields\nfrom TCP/IP headers. Using Wireshark, you should be able to tell if you are formatting outgoing\npackets correctly, and if you are correctly parsing incoming packets.\n</p><p>\n<h2>Language</h2>\nYou can write your code in whatever language you choose, as long as your code compiles and runs\non a <b>stock</b> copy of Ubuntu 20.04 <b>on the command line</b>.\n</p><p>\nBe aware that many languages do not support development using raw sockets. I am making an\nexplicit exception for Java, allowing the use of the RockSaw library. If you wish to program in\na language (other than Java) that requires third party library support for raw socket programming,\n<b>ask me for permission</b> before you start development.\n</p><p>\nAs usual, do not use libraries that are not installed by default on Ubuntu 20.04\n(with the exception of RockSaw). Similarly, your code must compile and run on the\ncommand line. You may use IDEs (e.g. Eclipse) during development, but do not turn in your IDE\nproject without a Makefile. Make sure you code has <b>no dependencies</b> on your IDE.\n</p><p>\n<h2>Submitting Your Project</h2>\nBefore turning in your project, you and your partner(s) must register your group. To register yourself\nin a group, execute the following script:\n<pre>$ /course/cs5700f20/bin/register project4 [team name]</pre>\nThis will either report back success or will give you an error message.  If you have trouble registering,\nplease contact the course staff. <b>You and your partner(s) must all run this script with the same \n[team name]</b>. This is how we know you are part of the same group.\n</p><p>\nTo turn-in your project, you should submit your (thoroughly documented) code along with three other files:\n<ul><li>A Makefile that compiles your code.</li>\n<li>A plain-text (no Word or PDF) README file. In this file, you should briefly describe your high-level\napproach, what TCP/IP features you implemented, and any challenges you faced. <b>You must also include a detailed description of which student worked on which part of the code.</b></li>\n<li>If your code is in Java, you must include a copy of the RockSaw library.</li>\n</ul>\nYour README, Makefile, source code, external libraries, etc. should all be placed in a directory. You submit\nyour project by running the turn-in script as follows:\n<pre>$ /course/cs5700f20/bin/turnin project4 [project directory]</pre>\n[project directory] is the name of the directory with your submission. The script will print out every\nfile that you are submitting, so make sure that it prints out all of the files you wish to submit!\n\n<b>Only one group member needs to submit your project.</b> Your group may submit as many times as you\nwish; only the last submission will be graded, and the time of the last submission will determine\nwhether your assignment is late.\n</p><p>\n<h2>Grading</h2>\nThis project is worth 16 points. You will receive full credit if 1) your code compiles, runs, and correctly\ndownloads files over HTTP, 2) you have not used any illegal libraries, and 3) you use the correct type of\nraw socket. All student code will be scanned by plagarism\ndetection software to ensure that students are not copying code from the Internet or each other.\n</p><p>\n5 points will be awarded for each of the three protocols you must implement, i.e. 5 points for HTTP,\n5 ponts for TCP, and 5 points for IP. 1 point will be awarded for your documentation. Essentially,\n6 points should be easy to earn; the other 10 are the challenge. \n</p><p>\n<h2>Extra Credit</h2>\nThere is an opportunity to earn 2 extra credit points on this assignment. To earn these points, you must\n'
        ippkt = ip.deserialize_ip(bytearray(recvdbytes))
        pkt = tcp.deserialize_tcp(ippkt.data)

        self.assertEqual(pkt.sport, 80)
        self.assertEqual(pkt.dport, 60667)
        self.assertEqual(pkt.seq, 2073116320)
        self.assertEqual(pkt.ack, 76)
        self.assertEqual(pkt.dataofs, 5)
        self.assertEqual(pkt.flags, 'AP')
        self.assertEqual(pkt.window, 64240)
        self.assertEqual(hex(pkt.chksum), hex(0x2a80))
        self.assertEqual(pkt.urgptr, 0)

        # not gonna bother checking the whole thing for now
        self.assertTrue(pkt.data.decode('ascii').startswith('e on a stock Ubuntu Linux'))
        self.assertTrue(pkt.data.decode('ascii').endswith('To earn these points, you must\n'))


if __name__ == '__main__':
    unittest.main()
