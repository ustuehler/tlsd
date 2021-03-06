import sys

# While this software project as whole may or may not fully support Python 3,
# this module at least supports both, Python 2.7 and 3.x
if sys.version_info[0] > 2:
    # The asyncio library is now a core part of Python 3
    import asyncio
else:
    # Backported asyncio library for Python 2, but no longer maintained
    import trollius as asyncio

from socket import error, socket, getaddrinfo, AF_INET, SOCK_STREAM, IPPROTO_TCP

from tlsd.diverters import AbstractDiverter

TCP_BACKLOG = 10

class ListenerSetupError(StandardError):
    pass

class TCPDiverterProtocol(asyncio.Protocol):
    pass

class TCPDiverter(AbstractDiverter):
    def __init__(self, port, host='127.0.0.1'):
        AbstractDiverter.__init__(self)
        self.host = host
        self.port = port

    def listen(self):
        sock = None
        for res in getaddrinfo(self.host, self.port, AF_INET, SOCK_STREAM, IPPROTO_TCP):
            family, socktype, proto, canonname, sockaddr = res
            try:
                sock = socket(family, socktype, proto)
            except error as msg:
                print 'socket:', e
                sock = None
                continue
            try:
                sock.bind(sockaddr)
                sock.listen(TCP_BACKLOG)
            except error as msg:
                print 'bind/listen:', msg
                sock.close()
                sock = None
            break
        if sock is None:
            raise ListenerSetupError('failed to listen on %s:%d' % (self.host, self.port,))
        return sock

    def divert(self):
        proxy_sock = self.listen()
        loop = asyncio.get_event_loop()
        loop.create_server(lambda: TCPAnalyzerProtocol(), self.host, self.port)
        loop.run_forever()
        loop.close()
