class TLSEnforcer(object):
    class CertificateRejectedError(StandardError):
        def __init__(self, tls_context, certificate):
            StandardError.__init__(self, 'certificate rejected in context %s: %s' % (tls_context.summary(), certificate.subject()))
            self.tls_context = tls_context
            self.certificate = certificate

    def __init__(self, tls_analyzer, rules):
        self.rules = rules
        tls_analyzer.subscribe(self, 'on_connect')

    def on_connect(self, tls_session):
        tls_session.client.subscribe(self, 'on_server_name_indication', 'on_application_data')
        tls_session.server.subscribe(self, 'on_certificates', 'on_application_data')

    def on_server_name_indication(self, tls_context, server_names):
        self.log_info(tls_context, 'SNI: %s' % (map(lambda x: x.data, server_names),))

    def on_certificates(self, tls_context, certificates):
        c = certificates[0]
        self.log_info(tls_context, 'subject: %s ' % c.subject())
        c = certificates[len(certificates)-1]
        self.log_info(tls_context, 'root: %s ' % c.issuer())

    def on_application_data(self, tls_context, data):
        self.enforce_rules(tls_context)

    def enforce_rules(self, tls_context):
        tls_session = tls_context.session
        match = self.rules.match(tls_session)
        if match != None:
            self.log_info(tls_context, match.summary())

        if match != None and match.action == 'block':
            if match.block_policy == 'close':
                tls_context.close()
            else:
                tls_session.block()
        else:
            tls_session.passthrough()

    def log_info(self, tls_context, msg):
        print '%s %s' % (tls_context.summary(), msg)
