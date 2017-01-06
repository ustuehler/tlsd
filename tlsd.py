#!/usr/bin/env python

import sys
import socket
from string import join

from scapy.layers.inet import IP, TCP
from scapy.layers import x509
from scapy_ssl_tls.ssl_tls import TLSCertificateList, TLSExtServerNameIndication
from scapy.utils import rdpcap
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate

from tlsd.analyzers.tcp import TCPAnalyzer
from tlsd.analyzers.tls import TLSAnalyzer

# listening divert(4) port
port = 700

# performance/protocol relevant?
bufsize = 16384

socket.IPPROTO_DIVERT = 258

class TLSEnforcer(object):
    def __init__(self, tls_analyzer):
        tls_analyzer.subscribe(self, 'on_connect')

    def on_connect(self, tls_session):
        tls_session.client.subscribe(self, ('on_tls_record'))
        tls_session.server.subscribe(self, ('on_tls_record'))

    def on_tls_record(self, tls_context, tls_record):
        if tls_record.haslayer(TLSExtServerNameIndication):
            self.log_info(tls_context, 'SNI: %s' % (map(lambda x: x.data, tls_record[TLSExtServerNameIndication].server_names),))

        elif tls_record.haslayer(TLSCertificateList):
            for certificate in tls_record[TLSCertificateList].certificates:
                cert = load_certificate(FILETYPE_ASN1, str(certificate.data))
                self.log_info(tls_context, 'subject: /%s ' % join(map(lambda x: x[0] + '=' + x[1], cert.get_subject().get_components()), '/'))

    def log_info(self, tls_context, msg):
        summary = tls_context.tcp_stream.summary()
        if tls_context.tcp_stream.initiator:
            mode = 'client'
        else:
            mode = 'server'
        print '%s %s %s' % (summary, mode, msg)

tcp_analyzer = TCPAnalyzer()
tls_analyzer = TLSAnalyzer(tcp_analyzer)
tls_enforcer = TLSEnforcer(tls_analyzer)

# TODO: IPv6
def inspect(packet):
    tcp_analyzer.write_ip(packet)

def divert():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_DIVERT)
    sock.bind(("0.0.0.0", port))
    while True:
        packet, address = sock.recvfrom(bufsize)
        try:
            inspect(IP(packet))
        except:
            print '--- Exception ---'
            pass
        sock.sendto(packet, address)

def replay(pcapfile):
    for packet in rdpcap(pcapfile):
        if packet.haslayer(IP):
            inspect(packet[IP])

def usage_error(msg):
    print >> sys.stderr, sys.argv[0] + ': ' + msg
    sys.exit(2)

def main():
    if len(sys.argv) == 1:
        divert()
    elif len(sys.argv) == 2:
        replay(sys.argv[1])
    else:
        usage_error('too many arguments')

if __name__ == '__main__':
    main()
