import random
import signal
import sys
import time

from tcp import TCP, deserialize_tcp

PACKETSIZE = 1024  # estimated average size of a packet. used so that we can use a packet-based congestion window


def handler(signum, frame):
    """Handler for timing out recv"""
    raise TimeoutError()


class TransportLayer:
    """Handles all functionality of the transport layer and implements TCP"""
    ntwk = None  # networklayer.NetworkLayer object
    established = False  # whether the 3 way handshake has been done yet

    sport = None  # local port we are bound to
    dport = None  # remote port we are connected to

    seq = random.randint(0, 4294967295)  # initial seq
    ack = 0  # initial ack

    window = 8192
    advert_wnd = 8192  # just a guess for what the receiver's will be
    cwnd = 1

    timeout = 60  # timeout

    # list of (expected ack, timestamp, packet itself)
    # used to track when packets have been dropped
    trackinginfo = []

    # list of (packet seq, packet data)
    # used for handling out of order packets
    unsentpacketslist = []

    def __init__(self, ntwk, sport, dport, debug=False):
        self.ntwk = ntwk
        self.sport = sport
        self.dport = dport
        self.debug = debug

    def send(self, data):
        """
        Sends the given string data over the TCP connection.

        tcp (bytearray) - the data to send over the network
        """
        sentdata = 0
        while sentdata < len(data):
            effdata = data[sentdata:min(self.advert_wnd, self.cwnd * PACKETSIZE)]
            # first data will be delivered as the final step in the 3 way handshake
            if not self.established:
                self.__connect(effdata)
                self.established = True
            else:
                tcppkt = TCP(data=effdata)
                self.__send_packet(tcppkt)

            self.seq += len(data)
            sentdata += len(data)

    def __track(self, tcppkt):
        """Tracks the given packet by storing the ACK we expect to receive for it, the time at which we sent it, and the
        packet itself so that we can retransmit it.

        tcppkt (TCP) - tcp packet object to track
        """

        expectedack = tcppkt.seq
        if tcppkt.data is not None:
            expectedack += len(tcppkt.data)

        ts = time.time()

        self.trackinginfo.append((expectedack, ts, tcppkt))

    def __check_retransmit(self, tcppkt):
        """
        Iterates over the list of packets we've sent looking for any packets that have timed out waiting for an ACK. For
        any packets that have timed out, this function retransmits them. If this packet is a match for a sent packet that
        has not timed out, then it simply removes that packet from the tracking list.

        tcppkt (TCP) - a TCP packet object that was just received from the network. If this is None, then the code is
                       requesting to retransmit only packets that have timed out. This is useful if we never receive
                       ACKs from the server
        """
        ts = time.time()

        rmvidx = []
        for i in range(len(self.trackinginfo)):
            pktinfo = self.trackinginfo[i]

            if ts - pktinfo[1] >= self.timeout:
                # timeout -- reset cwnd, remove tracking info, and retransmit
                self.cwnd = 1
                rmvidx.append(i)
                self.__send_packet(pktinfo[2])

            elif tcppkt is not None and pktinfo[0] == tcppkt.ack:
                # successfully acked -- increment cwnd and remove tracking info
                self.cwnd = min(self.cwnd + 1, 1000)
                rmvidx.append(i)

        if self.debug:
            print('removing {} tracked packets'.format(len(rmvidx)))

        # for any packets that timed out or were acked successfully, stop tracking them
        for idx in reversed(rmvidx):
            del self.trackinginfo[idx]

    def __send_packet(self, tcppkt):
        """
        Sends a TCP packet object over the network. Private helper function of this class

        tcppkt (TCP) - TCP packet object to send
        """
        # set these fields to avoid redundancy in caller
        tcppkt.sport = self.sport
        tcppkt.dport = self.dport
        tcppkt.seq = self.seq
        tcppkt.ack = self.ack
        tcppkt.window = self.window

        # track the packet, then send it
        self.__track(tcppkt)
        self.ntwk.send(tcppkt, self.debug)

    def __return_all_valid_packets(self, current_pktdata):
        """append previously received out of order packets if they match next ack"""
        should_look_for_more = False
        while True and len(self.unsentpacketslist) > 0:
            for i in range(len(self.unsentpacketslist)):
                pktseq = (self.unsentpacketslist[i])[0]
                pktdata = (self.unsentpacketslist[i])[1]
                if pktseq == self.ack:
                    should_look_for_more = True
                    current_pktdata += pktdata
                    if pktdata is not None:
                        self.ack = self.ack + len(pktdata)
                    del self.unsentpacketslist[i]
                    break
            
            if not should_look_for_more:
                break
        return current_pktdata

    def __append_packet_to_list(self, tcppkt):
        """ Append out of order packet to the list. Duplicates will not be discarded"""
        flag = True
        for i in range(len(self.unsentpacketslist)):
            pkt = self.unsentpacketslist[i]
            if tcppkt.seq == pkt[0]:
                flag = False
                break
        if flag:
            self.unsentpacketslist.append((tcppkt.seq, tcppkt.data))

    def recv(self):
        """Receives a packet from the network and returns the TCP payload as a bytearray"""
        success = False
        exactseq_pktdata = None

        signal.signal(signal.SIGALRM, handler)

        while not success:
            signal.alarm(self.timeout)

            # receive IP packet from network layer or time out
            # in addition to having self.trackinginfo, we must also implement a timeout here
            # because we may never get any ACKs at all and still need to be able to retransmit
            try:
                ippkt = self.ntwk.recv(self.debug)
            except TimeoutError:
                print('timeout')
                self.__check_retransmit(None)
                continue

            signal.alarm(0)  # reset alarm
            if ippkt.proto != 6:
                print('wrong ip protocol')
                continue

            # extract TCP packet from it
            tcppkt = deserialize_tcp(ippkt.data)

            if tcppkt.sport != self.dport or tcppkt.dport != self.sport:
                print('wrong ports received by tcp')
                continue

            if self.debug:
                tcppkt.show()

            # exit if reset (we don't handle that)
            if tcppkt.flags == 'R':
                sys.exit('Received reset from remote server')

            # break early if this is the FIN packet
            if 'F' in tcppkt.flags:
                return tcppkt.data

            self.advert_wnd = tcppkt.window

            # handle ack. may have to retransmit some packets
            if 'A' in tcppkt.flags:
                self.__check_retransmit(tcppkt)

            # out of order packet are added to list
            if self.ack < tcppkt.seq <= self.ack + self.window:
                self.__append_packet_to_list(tcppkt)
            elif self.ack == tcppkt.seq:
                success = True

                self.seq = tcppkt.ack

                if tcppkt.data is not None:
                    self.ack = self.ack + len(tcppkt.data)

                exactseq_pktdata = tcppkt.data

            # ack last received packet
            ackpkt = TCP(flags='A')
            self.__send_packet(ackpkt)

        return self.__return_all_valid_packets(exactseq_pktdata)

    def __connect(self, data):
        """
        Connects to the remote host by performing TCP's 3-way handshake, sending the given data with the final ACK
        
        data (bytearray) - data to be sent with final ACK
        """
        if not self.ntwk.connected:
            self.ntwk.connect()

        # 3 way handshake
        syn = TCP(flags='S')
        self.__send_packet(syn)
        synack_ip = self.ntwk.recv(self.debug)
        synack = deserialize_tcp(synack_ip.data)

        if self.debug:
            synack.show()

        self.seq = synack.ack
        self.ack = synack.seq + 1

        ackpkt = TCP(flags='A',
                     data=data)
        self.__send_packet(ackpkt)
        resp = self.ntwk.recv(self.debug)   # ignore first packet received
        tcpresp = deserialize_tcp(resp.data)

        if self.debug:
            tcpresp.show()

        # alert if reset sent back. Likely means iptables weren't set
        if 'R' in tcpresp.flags:
            sys.exit('Received reset after ACK in 3 way handshake. Maybe you forgot to edit iptables?')

    def shutdown(self):
        """
        Gracefully shuts down the connection to the remote server by sending a FIN packet, then ACKing all incoming
        packets until a FIN is received from the server
        """
        # send FIN
        finpkt = TCP(flags='F')
        self.__send_packet(finpkt)

        # read response
        resp_ip = self.ntwk.recv(self.debug)
        tcpresp = deserialize_tcp(resp_ip.data)

        # ack all packets we receive until we see a FIN from the server
        while True:
            if self.ack == tcpresp.seq:
                self.seq = tcpresp.ack

            # ack last received packet
            ackpkt = TCP(flags='A')
            self.__send_packet(ackpkt)

            resp_ip = self.ntwk.recv(self.debug)
            tcpresp = deserialize_tcp(resp_ip.data)

            if 'F' in tcpresp.flags:
                break

        self.ntwk.shutdown()