import socket

socket.IPPROTO_DIVERT = 258

from scapy.layers.inet import IP

from tlsd.diverters import AbstractDiverter

# performance/protocol relevant?
DEFAULT_BUFSIZE = 16384

class RawDiverter(AbstractDiverter):
    def __init__(self, port, bufsize = DEFAULT_BUFSIZE):
        AbstractDiverter.__init__(self)
        self.port = port
        self.bufsize = bufsize

    def divert(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_DIVERT)
        sock.bind(("0.0.0.0", self.port))

        while True:
            data, address = sock.recvfrom(self.bufsize)
            self.handle_ip_packet(packet = IP(data))
            # TODO: drop packet if the connection is now closed
            sock.sendto(data, address)
