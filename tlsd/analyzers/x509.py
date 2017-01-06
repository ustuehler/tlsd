from string import join
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate
#from sha import sha

class Certificate(object):
    def __init__(self, data):
        #print 'data len=%d sha=%s' % (len(data), sha(data).hexdigest(),)
        self.cert = load_certificate(FILETYPE_ASN1, data)

    def subject(self):
        return '/' + join(
                map(lambda x: x[0] + '=' + x[1],
                    sorted(self.cert.get_subject().get_components())),
                '/')

    def __str__(self):
        return self.subject()
