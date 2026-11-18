from dataclasses import dataclass

@dataclass(frozen=True)
class Packet:
    stream: int
    offset: int
    data: bytes
    final: bool = False

    @property
    def end(self):
        return self.offset + len(self.data)
