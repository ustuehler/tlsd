class Observable(object):
    def __init__(self):
        self.observers = dict()

    def subscribe(self, observer, *methods):
        #print '%s.subscribe(%s, %s)' % (type(self).__name__, type(observer).__name__, methods)
        if len(methods) < 1:
            raise StandardError('missing argument')
        for method in methods:
            if not self.observers.has_key(method):
                self.observers[method] = list()
            self.observers[method].append(observer)

    def unsubscribe(self, observer, *methods):
        #print '%s.unsubscribe(%s, %s)' % (type(self).__name__, type(observer).__name__, methods)
        if len(methods) == 0:
            methods = self.observers.keys()
        for method in methods:
            if self.observers.has_key(method):
                self.observers[method].remove(observer)
                if len(self.observers[method]) == 0:
                    self.observers.pop(method)

    def notify(self, method, *args):
        if self.observers.has_key(method):
            for observer in list(self.observers[method]):
                #print '%s.notify(%s, %s)' % (type(self).__name__, type(observer).__name__, method)
                getattr(observer, method)(*args)
