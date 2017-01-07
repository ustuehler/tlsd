from tlsd.rules.tls import TLSSessionRule

rules = []
rules.append(TLSSessionRule('pass'))

def match(tls_session):
    for rule in rules:
        if rule.match(tls_session):
            return rule
    return None
