from tlsd.rules.tls import TLSSessionRule

rules = []

rule = TLSSessionRule('pass')
rules.append(rule)

def match(tls_session):
    for rule in rules:
        if rule.match(tls_session):
            return rule
    return None
