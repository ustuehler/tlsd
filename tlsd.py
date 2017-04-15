#!/usr/bin/env python

import argparse
import sys
from traceback import print_exc

from tlsd.diverters.pcap import PcapDiverter
from tlsd.diverters.tcp import TCPDiverter
from tlsd.diverters.raw import RawDiverter

from tlsd.analyzers.tcp import TCPAnalyzer
from tlsd.analyzers.tls import TLSAnalyzer

from tlsd.enforcers.tls import TLSEnforcer

from examples import rules

# listening divert(4) port
port = 700

def main():
    parser = argparse.ArgumentParser(description='Enforces the specified ruleset on TLS connections')
    parser.add_argument('-f', metavar='FILE', dest='file', type=str, help='Read captured packets from FILE')
    parser.add_argument('-l', metavar='PORT', dest='port', type=int, help='Listen on PORT for diverted TCP connections')
    parser.add_argument('-r', action='store_true', dest='raw', help='Listen on PORT for diverted TCP/IP packets')
    args = parser.parse_args()

    if args.file == None and args.port == None:
        raise parser.error('either -f or -l must be specified')
    if args.file != None and args.port != None:
        raise parser.error('option -f and -l are mutually exclusive')
    if args.port == None and args.raw:
        raise parser.error('option -r must be used together with -l')

    if args.file:
        diverter = PcapDiverter(args.file)
    elif args.raw:
        diverter = RawDiverter(args.port)
    else:
        diverter = TCPDiverter(args.port)

    tcp_analyzer = TCPAnalyzer(diverter)
    tls_analyzer = TLSAnalyzer(tcp_analyzer)
    tls_enforcer = TLSEnforcer(tls_analyzer, rules)

    diverter.divert()

def divert_connections(parser, port):
    parser.error('option -l without -r is currently not implemented')

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

# TODO: IPv6
def inspect(packet):
    tcp_analyzer.write_ip(packet)

if __name__ == '__main__':
    main()
