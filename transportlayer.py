import random
import sys

from tcp import TCP, deserialize_tcp

"""
1 minute timeout for packets to be dropped:
 - for each packet we send, track time stamp and what the expected ack would be for it
    - list of (expected ack, timestamp, packet itself)
 - for every packet received, get timestamp. iterate over list. if we see a timestamp that was over one minute ago,
   retransmit it and reset cwnd. if we see the expected ack and the timestamp is not one minute ago, remote it from the list

handle out or order packets:
 - track next expected seq
 - when we receive a packet, compare seq with expected
    - if the are equal, deliver to upper layer. iterate over list, look for packets that arrived out of order. append all
      the data of all these packets in order and deliver them to the upper layer
    - if seq > expected, out of order packet. save it to some list ****
    - if seq < expected, ignore it. potentially duplicate
    
track window size:
 - initial window size = 8192 (from scapy)
 - when we receive a packet, decrement window by packet size
 - when we send an ack, add packet size back to the window

detect packets with seq outside of window:
 - when we receive a packet, if seq > window, ignore it

congestion window management:
 - add cwnd member variable. initially set to 1
 - for every ack we receive, increment by 1 until it reaches 1000
 - when a packet is dropped, reset cwnd
"""


class TransportLayer:
    """Handles all functionality of the transport layer and implements TCP"""
    ntwk = None  # networklayer.NetworkLayer object
    established = False  # whether the 3 way handshake has been done yet

    sport = None  # local port we are bound to
    dport = None  # remote port we are connected to

    seq = random.randint(0, 4294967295)  # initial seq
    ack = 0  # initial ack

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
        # first data will be delivered as the final step in the 3 way handshake
        if not self.established:
            self.__connect(data)
            self.established = True
        else:
            tcppkt = TCP(data=data)
            self.__send_packet(tcppkt)

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

        self.ntwk.send(tcppkt, self.debug)

    def recv(self):
        """Receives a packet from the network and returns the TCP payload as a bytearray"""
        success = False
        tcppkt = None

        while not success:
            # receive IP packet from network layer
            ippkt = self.ntwk.recv(self.debug)
            if ippkt.proto != 6:
                continue

            # extract TCP packet from it
            tcppkt = deserialize_tcp(ippkt.data)

            if self.debug:
                tcppkt.show()

            # exit if reset (we don't handle that)
            if tcppkt.flags == 'R':
                sys.exit('Received reset from remote server')

            # break early if this is the FIN packet
            if 'F' in tcppkt.flags:
                return tcppkt.data

            # TODO modify window size. may need to add a state machine
            if self.ack == tcppkt.seq:
                success = True

                self.seq = tcppkt.ack

                if tcppkt.data is not None:
                    self.ack = self.ack + len(tcppkt.data)

            # ack last received packet
            ackpkt = TCP(flags='A')
            self.__send_packet(ackpkt)

        return tcppkt.data

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

        self.seq = synack.ack
        self.ack = synack.seq + 1

        ackpkt = TCP(flags='A',
                     data=data)
        self.__send_packet(ackpkt)
        self.ntwk.recv(self.debug)   # ignore first packet received

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
