from tlsd.utils import Observable
from scapy.layers.inet import IP, TCP

class TCPStream(Observable):
    def __init__(self, stream_id):
        Observable.__init__(self)
        self.id = stream_id
        self.seq = None
        self.closed = True
        self.initiator = None
        self.fragments = dict() # by sequence number

    def summary(self):
        return '%s:%d > %s:%d' % self.id

    def drop(self, packet, reason):
        #print '%s / dropped / %s' % (packet.summary(), reason)
        pass

    def write_tcp(self, packet):
        # TOOD: handle URG flag
        if self.seq == None and packet.flags == 0x2:     # SYN
            # initiator -> responder
            self.initiator = True
            self.handle_syn_or_syn_ack(packet)
            return
        elif self.seq == None and packet.flags == 0x12:  # SYN|ACK
            # responder -> initiator
            self.initiator = False
            self.handle_syn_or_syn_ack(packet)
            return
        elif self.seq == None:
            self.drop(packet, 'initial SYN or SYN|ACK not seen')
            return
        elif self.closed:
            self.drop(packet, 'stream is already closed')
            return

        # handle the packet as any other fragment
        self.handle_tcp_fragment(packet)

    def handle_tcp_fragment(self, packet):
        if packet.seq < self.seq:
            # sequence number too low
            self.drop(packet, 'sequence number too low (%d < %d)' % (packet.seq, self.seq))
        elif self.seq == packet.seq:
            # process next fragment in sequence
            while packet:
                self.handle_next_in_sequence(packet)
                # and dequeue all adjacent fragments, too
                packet = self.dequeue_tcp_fragment()
        else:
            # out-of-order fragment with higher sequence number
            self.queue_tcp_fragment(packet)

    def queue_tcp_fragment(self, packet):
        #print '%s / queued / seq=%d' % (packet.summary(), packet.seq)
        self.fragments[packet.seq] = packet

    def dequeue_tcp_fragment(self):
        packet = self.fragments.pop(self.seq, None)
        #if packet:
        #    print '%s / dequeued / seq=%d' % (packet.summary(), packet.seq)
        return packet

    def handle_next_in_sequence(self, packet):
        # all packets may contain data
        self.handle_tcp_data(packet)

        if (packet.flags & 0x5) != 0: # FIN|RST
            # stream/connection closed
            self.handle_fin_or_rst(packet)

    def handle_syn_or_syn_ack(self, packet):
        self.closed = False
        self.time = packet.time
        self.seq = packet.seq + 1
        #print '%s / opened / time=%s, seq=%d' % (packet.summary(), self.time, packet.seq)
        self.notify('on_open', self)

    def handle_tcp_data(self, packet):
        data = str(packet.payload)
        datalen = len(data)
        if datalen > 0:
            self.seq += datalen
            #print '%s / data / seq=%d len=%d' % (packet.summary(), packet.seq, datalen)
            self.notify('on_data', self, data)

    def handle_fin_or_rst(self, packet):
        # FIN: no more data from this end
        # RST: this end is done talking and listening
        self.close()
        #print '%s / closed / time=%s, seq=%d' % (packet.summary(), packet.time, packet.seq)

    def close(self):
        if self.closed:
            return True
        self.closed = True
        self.seq = None
        self.fragments = dict()
        self.notify('on_close', self)

class TCPConnection(Observable):
    def __init__(self, connection_id):
        Observable.__init__(self)
        self.id = connection_id
        self.streams = dict()
        self.initiator = None
        self.responder = None

    def summary(self):
        return '%s,%d,%s,%d' % self.id

    def write_tcp_ip(self, packet):
        stream_id = self.tcp_ip_stream_id(packet)
        stream = self.tcp_ip_stream(stream_id)
        stream.write_tcp(packet[TCP])

    def tcp_ip_stream_id(self, packet):
        return (packet.src, packet[TCP].sport,
                packet.dst, packet[TCP].dport,)

    def tcp_ip_stream(self, stream_id):
        if self.streams.has_key(stream_id):
            return self.streams[stream_id]
        else:
            stream = TCPStream(stream_id)
            self.streams[stream_id] = stream
            stream.subscribe(self, 'on_open', 'on_close')
            return stream

    def on_open(self, tcp_stream):
        if tcp_stream.initiator == True:
            self.initiator = tcp_stream
        elif tcp_stream.initiator == False:
            self.responder = tcp_stream

        if self.initiator and self.responder:
            self.notify('on_connect', self)

    def on_close(self, tcp_stream):
        self.streams.pop(tcp_stream.id)

        if tcp_stream.initiator == True:
            self.initiator = None
        elif tcp_stream.initiator == False:
            self.responder = None

        if not (self.initiator or self.responder):
            self.notify('on_disconnect', self)

class TCPAnalyzer(Observable):
    def __init__(self):
        Observable.__init__(self)
        self.connections = dict()

    def on_connect(self, tcp_connection):
        self.notify('on_connect', tcp_connection)

    def on_disconnect(self, tcp_connection):
        self.notify('on_disconnect', tcp_connection)

    def write_ip(self, packet):
        if packet.haslayer(TCP):
            connection = self.tcp_ip_connection(packet)
            connection.write_tcp_ip(packet)

    def tcp_ip_connection(self, packet):
        connection_id = self.tcp_ip_connection_id(packet)

        if self.connections.has_key(connection_id):
            return self.connections[connection_id]

        connection = TCPConnection(connection_id)
        connection.subscribe(self, 'on_connect','on_disconnect')

        self.connections[connection_id] = connection
        return connection

    def tcp_ip_connection_id(self, packet):
        '''Unique TCP connection identifier, irrespective of the flow
        direction in the given TCP/IP packet. This identifier may be
        confusing to humans and should be avoided in log output.'''

        a = (packet.src, packet[TCP].sport)
        b = (packet.dst, packet[TCP].dport)

        if a <= b:
            return tuple(a + b)
        else:
            return tuple(b + a)
