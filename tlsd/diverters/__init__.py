from tlsd.utils import Observable

class AbstractDiverter(Observable):
    def __init__(self):
        Observable.__init__(self)

    def handle_ip_packet(self, packet):
        self.notify('on_ip_packet', packet)
