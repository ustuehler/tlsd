#!/usr/bin/env python

import sys
import socket
from traceback import print_exc

from scapy.layers.inet import IP, TCP
from scapy.layers import x509
from scapy.utils import rdpcap

from tlsd.analyzers.tcp import TCPAnalyzer
from tlsd.analyzers.tls import TLSAnalyzer
from tlsd.enforcers.tls import TLSEnforcer

# listening divert(4) port
port = 700

# performance/protocol relevant?
bufsize = 16384

socket.IPPROTO_DIVERT = 258

from examples import rules

tcp_analyzer = TCPAnalyzer()
tls_analyzer = TLSAnalyzer(tcp_analyzer)
tls_enforcer = TLSEnforcer(tls_analyzer, rules)

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
        print_exc()
        return True

def divert():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_DIVERT)
    sock.bind(("0.0.0.0", port))
    while True:
        data, address = sock.recvfrom(bufsize)
        packet = IP(data)
        if enforce(packet):
            sock.sendto(data, address)
        else:
            #if packet.haslayer(TCP):
            if False:
                packet[TCP].flags = 'F'
                packet[TCP].payload = str()
                print 'tcp len=%d' % (len(packet[TCP]),)
                print 'ip len=%d' % (len(packet),)
                packet.len = len(packet)
                packet.show()
            sock.sendto(data, address)

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
