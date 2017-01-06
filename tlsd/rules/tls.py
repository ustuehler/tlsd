from tlsd.rules import Rule

class X509NameRule(Rule):
    pass

class CertificateRule(Rule):
    def __init__(self):
        self.subject = X509NameRule()
        self.issuer = X509NameRule()

class ServerNameListRule(Rule):
    pass

class CertificateListRule(Rule):
    def __init__(self):
        Rule.__init__(self)
        self.certs = [CertificateRule()]

class TLSContextRule(Rule):
    def __init__(self):
        self.server_names = ServerNameListRule()
        self.certificates = CertificateListRule()

    def match(self, tls_context):
        return self.server_names.match(tls_context.server_names) and \
                self.certificates.match(tls_context.certificates)


class TLSSessionRule(Rule):
    def __init__(self, action):
        self.action = action
        self.client = TLSContextRule()
        self.server = TLSContextRule()

    def match(self, tls_session):
        return self.client.match(tls_session.client) and \
                self.server.match(tls_session.server)
