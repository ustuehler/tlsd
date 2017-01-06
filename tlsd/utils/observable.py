class Observable(object):
    def __init__(self):
        self.observers = dict()

    def subscribe(self, observer, *methods):
        #print '%s.subscribe(%s, %s)' % (type(self).__name__, type(observer).__name__, methods)
        for method in methods:
            if not self.observers.has_key(method):
                self.observers[method] = list()
            self.observers[method].append(observer)

    def unsubscribe(self, observer, *methods):
        #print '%s.unsubscribe(%s, %s)' % (type(self).__name__, type(observer).__name__, methods)
        for method in methods:
            if self.observers.has_key(method):
                self.observers[method].remove(observer)
                if len(self.observers[method]) == 0:
                    self.observers.remove(method)

    def notify(self, method, *args):
        if self.observers.has_key(method):
            for observer in list(self.observers[method]):
                #print '%s.notify(%s, %s)' % (type(self).__name__, type(observer).__name__, method)
                getattr(observer, method)(*args)
