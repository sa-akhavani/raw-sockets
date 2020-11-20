import socket
import sys
import time

import ip
import io


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

    fraginfo = dict()  # maps packet id -> info needed to manage fragmentation

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

    class FragObject:
        """Class used to store fragmentation metadata"""
        def __init__(self, buffer, seenoffsets, bytesrecvd, totalbytes, seenfinal, firstpkt):
            self.buffer = buffer  # buffer containing reassembled data
            self.seenoffsets = seenoffsets  # set of all offsets we've seen
            self.bytesrecvd = bytesrecvd  # total unique bytes received
            self.totalbytes = totalbytes  # total bytes in the entire datagram payload
            self.seenfinal = seenfinal  # whether we've seen the final packet
            self.firstpkt = firstpkt  # the first packet we received (store so we can make a new IP packet)

    def handle_fragment(self, ip_pkt, debug=False):
        """
        Handles a fragment of an IP datagram.

        ip_pkt (IP) - IP packet that is part of a fragment
        debug (bool) - whether to print debug information

        return - the fully reassembled IP packet or None if there are still fragments to be received
        """

        # create new entry
        if ip_pkt.idnum not in self.fraginfo:
            self.fraginfo[ip_pkt.idnum] = self.FragObject(io.BytesIO(), {}, 0, -1, False, ip_pkt)

        # check for a reassembled packet that is too big
        if 20 + ip_pkt.frag * 8 + len(ip_pkt.data) > 65535:
            print('IP fragmentation overflow attempt')
            return None

        # copy data into buffer if this is not a duplicate
        entry = self.fraginfo[ip_pkt.idnum]
        if ip_pkt.frag not in entry.seenoffsets:
            entry.buffer.seek(ip_pkt.frag * 8)
            entry.buffer.write(ip_pkt.data)
            entry.bytesrecvd += len(ip_pkt.data)

        # if this is the last fragment, then we now know the total size of the buffer
        if ip_pkt.flags != 'M':
            entry.seenfinal = True
            entry.totalbytes = ip_pkt.frag * 8 + len(ip_pkt.data)

        # if we have copied all the byte in the payload, construct a new IP datagram and deliver it to the upper layer
        if entry.seenfinal and entry.bytesrecvd == entry.totalbytes:
            outpkt = ip.IP(version=4, ihl=5, tos=entry.firstpkt.tos, len=20 + entry.totalbytes, id=entry.firstpkt.idnum,
                           flags='', frag=0, ttl=entry.firstpkt.ttl, proto=entry.firstpkt.proto,
                           src=entry.firstpkt.src, dst=entry.firstpkt.dst,
                           data=bytearray(entry.buffer.getvalue()))

            if debug:
                print('reassembled datagram')
                outpkt.show()

            return outpkt

        # None signals that the packet is not fully assembled yet
        return None

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
        # minute, which will interrupt this function. Since the network layer must time out after 3 minutes, we must
        # track the time across multiple function calls.
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

            # only return packets with the correct src/dst addresses and which have a valid checksum
            if ip_pkt.src == self.remote_addr and ip_pkt.dst == self.local_addr:

                # reset timer flag
                self.firstrecv = True

                if self.__valid_checksum(ip_pkt):
                    # check for fragmentation
                    if ip_pkt.flags == 'M' or ip_pkt.frag > 0:
                        maybepkt = self.handle_fragment(ip_pkt, debug)
                        if maybepkt is not None:
                            return maybepkt
                        else:
                            continue
                    return ip_pkt

            print('incorrect addresses or checksum')
