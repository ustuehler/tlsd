from scapy.layers.inet import IP
from scapy.utils import rdpcap

from tlsd.diverters import AbstractDiverter

class PcapDiverter(AbstractDiverter):
    def __init__(self, pcapfile):
        AbstractDiverter.__init__(self)
        self.pcapfile = pcapfile

    def divert(self):
        for packet in rdpcap(self.pcapfile):
            if packet.haslayer(IP):
                self.handle_ip_packet(packet[IP])
