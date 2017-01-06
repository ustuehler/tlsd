class TLSEnforcer(object):
    class CertificateRejectedError(StandardError):
        def __init__(self, tls_context, certificate):
            self.tls_context = tls_context
            self.certificate = certificate

    def __init__(self, tls_analyzer):
        tls_analyzer.subscribe(self, 'on_connect')

    def on_connect(self, tls_session):
        tls_session.client.subscribe(self, 'on_server_name_indication')
        tls_session.server.subscribe(self, 'on_certificates')

    def on_server_name_indication(self, tls_context, server_names):
        self.log_info(tls_context, 'SNI: %s' % (map(lambda x: x.data, server_names),))

    def on_certificates(self, tls_context, certificates):
        for cert in certificates:
            if self.certificate_valid(cert):
                self.log_info(tls_context, 'subject: %s ' % cert.subject())
            else:
                self.log_info(tls_context, 'certificate rejected')
                #tls_context.error(TLSEnforcer.CertificateRejectedError, cert)

    #def on_tls_record(self, tls_context, tls_record):
    #    self.log_info(tls_context, tls_record.summary())

    def certificate_valid(self, cert):
        return True

    def log_info(self, tls_context, msg):
        print '%s %s' % (tls_context.summary(), msg)
