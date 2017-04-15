import unittest

from tlsd.analyzers.tcp import TCPConnection, TCPStream
from tlsd.analyzers.tls import TLSSession
from tlsd.rules.tls import TLSSessionRule

class TestSimplePassRule(unittest.TestCase):

    def setUp(self):
        initiator_id = ('127.0.0.1', 12345, '127.0.0.1', 443)
        responder_id = ('127.0.0.1', 443, '127.0.0.1', 12345)

        tcp_connection = TCPConnection(initiator_id)
        tcp_connection.initiator = TCPStream(initiator_id)
        tcp_connection.initiator.initiator = True
        tcp_connection.responder = TCPStream(responder_id)

        self.tls_session = TLSSession(tcp_connection)

    def test_match(self):
        session = self.tls_session
        rule = TLSSessionRule('pass')
        self.assertTrue(rule.match(session))

if __name__ == '__main__':
    unittest.main()
