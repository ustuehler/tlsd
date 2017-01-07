from string import join
from tlsd.rules import Rule

class TLSSessionRule(Rule):
    def __init__(self, action):
        Rule.__init__(self)
        self.action = action

    def match(self, tls_session):
        return True

    def summary(self):
        return self.action
