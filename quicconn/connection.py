from .flow import FlowControl
from .migration import Peer
from .recovery import Recovery
from .streams import Stream

class Connection:
    def __init__(self, fail=()):
        self.streams = {}
        self.flow = FlowControl()
        self.peer = Peer(fail)

    def receive(self, packet):
        stream = self.streams.setdefault(packet.stream, Stream(packet.stream))
        if not stream.add(packet):
            return b""
        self.flow.observe(packet)
        payload = stream.contiguous()
        if payload:
            self.peer.write(packet.stream, payload)
        return payload

    def snapshot(self):
        return Recovery().save(self.streams, self.flow)

    def migrate(self, state):
        self.streams = Recovery().load(state)
