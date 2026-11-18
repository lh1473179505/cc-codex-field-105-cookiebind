class Subscriber:
    def __init__(self, name, fail=()):
        self.name = name
        self.fail = set(fail)
        self.rows = []

    def send(self, notice):
        if notice.body in self.fail:
            raise OSError(self.name + ":" + notice.body)
        self.rows.append(notice.body)

class Registry:
    def __init__(self):
        self.subscribers = {}

    def add(self, subscriber):
        self.subscribers[subscriber.name] = subscriber

    def ordered(self):
        return [self.subscribers[k] for k in sorted(self.subscribers)]
