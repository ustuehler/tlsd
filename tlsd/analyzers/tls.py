from scapy_ssl_tls.ssl_tls import TLS, TLSCertificateList, TLSExtServerNameIndication
from tlsd.analyzers.x509 import Certificate
from tlsd.utils import Observable

class TLSContext(Observable):
    def __init__(self, session, tcp_stream):
        Observable.__init__(self)
        self.session = session
        self.tcp_stream = tcp_stream
        self.server_names = list()
        self.certificates = list()
        self.incomplete_record = str()
        tcp_stream.subscribe(self, 'on_data')

    def role(self):
        if self.tcp_stream.initiator:
            return 'client'
        else:
            return 'server'

    def summary(self):
        return self.session.summary() + ' ' + self.role()

    def on_data(self, tcp_stream, data):
        '''Receives data from the analyzed TCP stream. This is the data that
        gets sent in only one direction, depending on the role of the peer.
        '''
        data = self.incomplete_record + data
        #print '%s: available data: len=%d' % (self.role(), len(data))
        complete_len = 0
        for record in TLS(data).records:
            record_len = record.length + 5 # mimum size of TLSRecord

            if len(data) >= complete_len + record_len:
                #print '%s: complete record: len=%d/%d' % (self.role(), record_len, record.length)
                complete_len += record_len
                self.on_tls_record(record)
            else:
                #print '%s: incomplete record: len=%d/%d' % (self.role(), record_len, record.length)
                break
        self.incomplete_record = data[complete_len:]
        #print '%s: remaining data: len=%d' % (self.role(), len(self.incomplete_record))

    def on_tls_record(self, record):
        self.notify('on_tls_record', self, record)

        if record.haslayer(TLSExtServerNameIndication):
            self.server_names = map(
                    lambda x: x,
                    record[TLSExtServerNameIndication].server_names)
            self.notify('on_server_name_indication', self, self.server_names)

        elif record.haslayer(TLSCertificateList):
            self.certificates = map(
                    lambda x: Certificate(str(x.data)),
                    record[TLSCertificateList].certificates)
            self.notify('on_certificates', self, self.certificates)
        elif record.content_type == 23: # application_data
            self.on_application_data(record)

    def on_application_data(self, record):
        self.notify('on_application_data', self, str(record.data))

    def passthrough(self):
        self.tcp_stream.unsubscribe(self, 'on_data')

class TLSSession(Observable):
    def __init__(self, tcp_connection):
        Observable.__init__(self)

        if not tcp_connection.initiator:
            raise StandardError('TCP connection without initiator')
        if not tcp_connection.responder:
            raise StandardError('TCP connection without responder')

        self.client = TLSContext(self, tcp_connection.initiator)
        self.server = TLSContext(self, tcp_connection.responder)

        self.tcp_connection = tcp_connection

        tcp_connection.subscribe(self, 'on_disconnect')

    def summary(self):
        '''Summarizes the TLS session in a single line. A TLS session is always
        identified by the client's TCP stream. The order of the "IP:port" tuple
        in the summary is always "initiator > responder".'''
        return self.client.tcp_stream.summary()

    def on_disconnect(self, tcp_connection):
        self.notify('on_disconnect', self)

    def passthrough(self):
        '''Stops analyzing the underlying TCP data flows.
        '''
        self.client.passthrough()
        self.server.passthrough()
        self.tcp_connection.unsubscribe(self, 'on_disconnect')

class TLSAnalyzer(Observable):
    def __init__(self, tcp_analyzer):
        Observable.__init__(self)
        self.sessions = dict()
        tcp_analyzer.subscribe(self, 'on_connect')

    def on_connect(self, tcp_connection):
        tls_session = TLSSession(tcp_connection)
        tls_session.subscribe(self, 'on_disconnect')
        self.sessions[tcp_connection.id] = tls_session
        self.notify('on_connect', tls_session)
        #print 'TLS sessions now open: %d' % len(self.sessions)

    def on_disconnect(self, tls_session):
        self.sessions.pop(tls_session.tcp_connection.id)
        self.notify('on_disconnect', tls_session)
        #print 'TLS sessions now open: %d' % len(self.sessions)
