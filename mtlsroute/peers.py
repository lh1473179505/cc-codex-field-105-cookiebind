from dataclasses import dataclass

@dataclass(frozen=True)
class Frame:
    key: str
    peer: str
    epoch: int
    payload: str

class Wire:
    def __init__(self, fail=()):
        self.rows = []
        self.fail = set(fail)

    def send(self, frame):
        if frame.payload in self.fail:
            raise OSError("wire rejected " + frame.payload)
        self.rows.append((frame.peer, frame.epoch, frame.payload))
