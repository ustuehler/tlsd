from string import join
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate
#from sha import sha

class X509Name(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '/' + join(
                map(lambda x: x[0] + '=' + x[1],
                    sorted(self.name.get_components())),
                '/')

class Certificate(object):
    def __init__(self, data):
        #print 'data len=%d sha=%s' % (len(data), sha(data).hexdigest(),)
        self.cert = load_certificate(FILETYPE_ASN1, data)

    def subject(self):
        return X509Name(self.cert.get_subject())

    def issuer(self):
        return X509Name(self.cert.get_issuer())

    def __str__(self):
        return self.subject()
