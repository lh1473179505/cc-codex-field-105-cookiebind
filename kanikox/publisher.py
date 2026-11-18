from pathlib import Path

from .context import ContextSnapshots
from .destination import Destinations
from .journal import PushJournal


class Publisher:
    def __init__(self, root):
        self.root = Path(root)
        self.contexts = ContextSnapshots(self.root / "contexts")
        self.destinations = Destinations(self.root)
        self.journal = PushJournal(self.root)
        self.sequence = 0

    def push(self, tag, files, fail=False):
        self.sequence += 1
        sequence = self.sequence
        digest = self.contexts.capture(files)
        tx = "tx-" + str(sequence)
        self.journal.append({"tx": tx, "sequence": sequence, "state": "packed", "tag": tag, "digest": digest})
        if fail:
            self.journal.append({"tx": tx, "sequence": sequence, "state": "aborted", "tag": tag, "digest": digest})
            raise RuntimeError("destination push failed")
        self.destinations.put(tag, digest, sequence)
        self.journal.append({"tx": tx, "sequence": sequence, "state": "pushed", "tag": tag, "digest": digest})
        return digest

    def rebuild(self, tag, files):
        return self.push(tag, files)
