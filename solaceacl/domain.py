from dataclasses import dataclass

@dataclass(frozen=True)
class Message:
    key: str
    epoch: int
    payload: str

class DurableSink:
    def __init__(self, fail=()):
        self.rows = []
        self.fail = set(fail)

    def append(self, message):
        if message.payload in self.fail:
            raise RuntimeError(message.payload)
        self.rows.append((message.epoch, message.payload))
