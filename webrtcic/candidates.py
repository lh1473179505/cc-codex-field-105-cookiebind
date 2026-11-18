from dataclasses import dataclass

@dataclass(frozen=True)
class Candidate:
    key: str
    generation: int
    address: str

class CandidatePool:
    def __init__(self):
        self.pending = {}
        self.applied = set()

    def stage(self, candidate):
        if candidate.key not in self.applied:
            self.pending[candidate.key] = candidate

    def drain(self):
        batch = [self.pending[k] for k in sorted(self.pending)]
        self.pending.clear()
        self.applied.update(c.key for c in batch)
        return batch
