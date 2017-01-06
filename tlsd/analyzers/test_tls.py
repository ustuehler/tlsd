import unittest

from tlsd.analyzers.tcp import TCPConnection
from tlsd.analyzers.tls import TLSSession

class TestEnforceOnPcapFile(unittest.TestCase):

    def test_enforce(self):
        self.assertTrue(True)

if __name__ == '__main__':
    unittest.main()
