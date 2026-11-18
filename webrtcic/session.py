from .candidates import CandidatePool
from .rollback import Journal
from .sdp import Description
from .transport import Transport

class Session:
    def __init__(self, fail=()):
        self.description = Description()
        self.pool = CandidatePool()
        self.transport = Transport(fail)
        self.journal = Journal()

    def trickle(self, candidates):
        for candidate in candidates:
            self.pool.stage(candidate)
        batch = self.pool.drain()
        for candidate in batch:
            self.journal.record(candidate)
            self.transport.connect(candidate)

    def restart(self):
        self.description.restart()

    def snapshot(self):
        return {"generation": self.description.generation,
                "applied": sorted(self.pool.applied), "journal": self.journal.export()}

    def restore(self, state):
        self.description.generation = state["generation"]
        self.pool.applied = set(state["applied"])
        self.journal.entries = list(state["journal"]["entries"])
