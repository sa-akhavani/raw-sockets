import socket
import sys
import time

import ip

"""
IP fragmentation assembly:
    upon receiving a packet, check if either flags == 'M' or frag > 0
    if true, check if resources allocated for reassembly
        if no resources allocate resources for fragmentation reassembly : 
            map id -> (buffer holding full packet, set of received frag offsets, total unique data received, whether we've received the final packet)
        copy frag data into buffer starting at index pkt.frag
        if flags != 'M': set final=true
         
    
"""


class NetworkLayer:
    """Handles all functionality of the network layer and implements IP"""
    # send and receive sockets
    ssock = None
    rsock = None

    local_addr = None
    remote_addr = None

    connected = False  # whether the raw sockets have been created and bound/connected
    firstrecv = True  # whether this is the first call to recv since we last received a packet
    recvstarttime = None

    MSS = 65535
    timeout = 180

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
        self.rsock.settimeout(self.timeout)

        self.local_addr = localaddrpair[0]
        self.remote_addr = remoteaddrpair[0]

        self.connected = True

    def shutdown(self):
        self.ssock.close()
        self.rsock.close()

    def settimeout(self, timeo):
        """
        Sets the timeout (in seconds) for receiving messages on rsock
        timeo (float) - timeout in seconds
        """
        self.timeout = timeo
        self.rsock.settimeout(self.timeout)

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
            print('sending')
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

        # This code enables the 3 minute timeout
        #
        # On the first call to this function since we last received a packet addressed to us, save the current time.
        #
        # On subsequent calls, compare the current time to the time since we last received a packet.
        #
        # This check is necessary because the transport layer raises an exception if a packet is not received after a
        # minute, which will interrupt this function. Since the network layer times out after 3 minutes, we must track
        # the time across multiple function calls.
        ts = time.time()
        if self.firstrecv:
            self.recvstarttime = ts
            self.firstrecv = False
        elif ts - self.recvstarttime >= self.timeout:
            sys.exit('No response from server after {} seconds. Connection assumed dead'.format(self.timeout))

        # receive in a loop until we get a packet from the remote server addressed to us
        while True:
            # this will never be executed as long as the TCP connection is doing its own timeouts, but is necessary if
            # a different transport layer protocol is used that still wants the 3-minute timeout from the network layer
            try:
                data = self.rsock.recv(self.MSS)
            except socket.timeout:
                sys.exit('Socket timeout after {} seconds. Connection assumed dead'.format(self.timeout))

            # deserialize packet
            ip_pkt = ip.deserialize_ip(bytearray(data))
            if debug:
                print('received')
                ip_pkt.show()

            if ip_pkt.flags == 'M' or ip_pkt.frag > 0:
                # TODO handle fragmentation
                pass

            # only return packets with the correct src/dst addresses and which have a valid checksum
            if ip_pkt.src == self.remote_addr and ip_pkt.dst == self.local_addr:
                self.firstrecv = True

                if self.__valid_checksum(ip_pkt):
                    return ip_pkt
