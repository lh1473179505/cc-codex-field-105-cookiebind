from .capture import Capture
from .handshake import Handshakes
from .reassembly import Reassembly
from .socket import Socket

class Endpoint:
    def __init__(self, fail=()):
        self.handshakes = Handshakes()
        self.reassembly = Reassembly()
        self.socket = Socket(fail)

    def open(self, session):
        return self.handshakes.open(session)

    def migrate(self, session):
        return self.handshakes.migrate(session)

    def receive(self, fragment):
        text = self.reassembly.accept(fragment)
        if text is not None:
            self.socket.send(fragment.session, text)
        return text

    def snapshot(self):
        return Capture().save(self.reassembly, self.handshakes)

    def restore(self, state):
        Capture().load(state, self.reassembly, self.handshakes)
