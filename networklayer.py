import socket
import sys
import time

import ip

"""
IP fragmentation assembly
"""


class NetworkLayer:
    """Handles all functionality of the network layer and implements IP"""
    # send and receive sockets
    ssock = None
    rsock = None

    local_addr = None
    remote_addr = None

    connected = False  # whether the raw sockets have been created and bound/connected

    MSS = 65535
    TIMEO = 180

    def connect(self, localaddrpair, remoteaddrpair):
        """
        Binds to the given local IP address and port and connects to the given remote IP address and port

        localaddrpair - 2-tuple with format (ip_address as a string, port as an int)
        remoteaddrpair - same as localaddrpair
        """
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ssock.connect(remoteaddrpair)

        self.rsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.rsock.bind(localaddrpair)
        self.rsock.settimeout(self.TIMEO)  # 3 minute timeout

        self.local_addr = localaddrpair[0]
        self.remote_addr = remoteaddrpair[0]

        self.connected = True

    def send(self, tcp, debug=False):
        """
        Sends the given tcp packet over the send socket

        tcp (TCP) - an unserialized TCP packet object to be send. Must be deserialized because the TCP checksum
            computation cannot be done without knowledge of the IP header
        debug (bool) - debug mode enabled or not. if True, then the packets are printed before sending them
        """
        # serialize once to get right size
        tcp_slz = tcp.serialize()
        ippkt = ip.IP(src=self.local_addr, dst=self.remote_addr, proto=6, len=20 + len(tcp_slz))

        # now compute checksum with new IP packet and send it
        tcp.compute_checksum(ippkt)

        if debug:
            # set data to packet itself to print both IP and TCP
            ippkt.data = tcp
            ippkt.show()

        ippkt.data = tcp.serialize()  # must reserialize to get correct checksum
        self.ssock.sendall(ippkt.serialize())

    def __valid_checksum(self, ip_pkt):
        """Returns whether the checksum provided in the IP packet is correct"""
        given_checksum = ip_pkt.chksum
        ip_pkt.compute_checksum()
        calculated_checksum = ip_pkt.chksum
        return given_checksum == calculated_checksum

    def recv(self, debug=False):
        """
        Receives data from the receive socket and deserializes it into an IP packet.

        debug (bool) - debug mode enabled or not. if True, then the received bytes and deserialized packet are printed
        """
        # get start time to enable 3-minute timeout
        # must do this because recv socket is promiscuous and we need to know when 3 minutes have elapsed since we heard
        # from the server we WANT to talk to, not just since we heard anything from the entire network
        start = time.time()

        while True:
            try:
                data = self.rsock.recv(self.MSS)
            except socket.timeout:
                sys.exit('Socket timeout after {} seconds. Connection assumed dead'.format(self.TIMEO))

            # terminate if we've been receiving for 3 minutes
            end = time.time()
            if end - start >= self.TIMEO:
                sys.exit('No response from remote server after {} seconds. Connection assumed dead'.format(self.TIMEO))

            if debug:
                print(data)

            # deserialize packet
            ip_pkt = ip.deserialize_ip(bytearray(data))
            if debug:
                ip_pkt.show()

            # only return packets with the correct src/dst addresses and which have a valid checksum
            if ip_pkt.src == self.remote_addr and ip_pkt.dst == self.local_addr:
                if self.__valid_checksum(ip_pkt):
                    return ip_pkt
