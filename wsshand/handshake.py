class Handshakes:
    def __init__(self):
        self.epochs = {}

    def open(self, session):
        self.epochs[session] = 1
        return self.epochs[session]

    def migrate(self, session):
        self.epochs[session] += 1
        return self.epochs[session]

    def current(self, session):
        return self.epochs[session]
