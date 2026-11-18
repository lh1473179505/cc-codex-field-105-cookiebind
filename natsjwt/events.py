from dataclasses import dataclass

@dataclass(frozen=True)
class Event:
    key: str
    seq: int
    barrier: int
    payload: str

class Sink:
    def __init__(self, fail=()):
        self.values = []
        self.fail = set(fail)

    def write(self, event):
        if event.payload in self.fail:
            raise OSError("sink rejected " + event.payload)
        self.values.append(event.payload)
