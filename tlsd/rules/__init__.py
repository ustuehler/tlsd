class Rule(object):
    def __init__(self):
        self.predicate = lambda b: True

    def match(self, thing):
        return self.predicate(thing)

    def eq(a):
        self.predicate = lambda b: a == b
