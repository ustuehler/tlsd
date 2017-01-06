#!/usr/bin/env python

import sys
import socket

from scapy.layers.inet import IP, TCP
from scapy.layers import x509
from scapy_ssl_tls.ssl_tls import TLSCertificateList, TLSExtServerNameIndication
from scapy.utils import rdpcap

from tlsd.analyzers.tcp import TCPAnalyzer
from tlsd.analyzers.tls import TLSAnalyzer
from tlsd.analyzers.x509 import Certificate

# listening divert(4) port
port = 700

# performance/protocol relevant?
bufsize = 16384

socket.IPPROTO_DIVERT = 258

class TLSEnforcer(object):
    class CertificateRejectedError(StandardError):
        def __init__(self, tls_context, certificate):
            self.tls_context = tls_context
            self.certificate = certificate

    def __init__(self, tls_analyzer):
        tls_analyzer.subscribe(self, 'on_connect')

    def on_connect(self, tls_session):
        tls_session.client.subscribe(self, 'on_server_name_indication')
        tls_session.server.subscribe(self, 'on_certificates')

    def on_server_name_indication(self, tls_context, server_names):
        self.log_info(tls_context, 'SNI: %s' % (map(lambda x: x.data, server_names),)

    def on_certificates(self, tls_context, certificates):
        for cert in certificates:
            if not self.certificate_valid(cert):
                self.log_info(tls_context, 'certificate rejected')
                raise TLSEnforcer.CertificateRejectedError(tls_context, cert)

            self.log_info(tls_context, 'subject: %s ' % cert.subject())

    def certificate_valid(self, cert):
        return False

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

def enforce(packet):
    try:
        inspect(packet)
        return True
    except TLSEnforcer.CertificateRejectedError as e:
        print '--- Certificate Rejected ---'
        print '%s' % e.certificate
        return False
    except StandardError as e:
        print '--- %s Ignored ---' % type(e).__name__
        print '%s' % e
        return True

def divert():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_DIVERT)
    sock.bind(("0.0.0.0", port))
    while True:
        packet, address = sock.recvfrom(bufsize)
        enforce(IP(packet))
        sock.sendto(packet, address)

def replay(pcapfile):
    for packet in rdpcap(pcapfile):
        if packet.haslayer(IP):
            enforce(packet[IP])

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
