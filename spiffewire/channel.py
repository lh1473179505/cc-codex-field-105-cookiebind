from dataclasses import dataclass

@dataclass(frozen=True)
class Packet:
    key: str
    spiffe_id: str
    generation: int
    body: str

class Channel:
    def __init__(self, fail=()):
        self.sent = []
        self.fail = set(fail)

    def deliver(self, packet):
        if packet.body in self.fail:
            raise RuntimeError("channel " + packet.body)
        self.sent.append(packet)
