import uuid
from pathlib import Path

from .checkpoint import Checkpointer
from .digests import BlobStore
from .entries import valid
from .journal import Journal


class ReleaseError(Exception):
    pass


class LogService:
    def __init__(self, root, keys):
        self.root = Path(root)
        self.keys = dict(keys)
        self.blobs = BlobStore(self.root / "blobs")
        self.journal = Journal(self.root / "journal")
        self.checkpoints = Checkpointer(self.root, self.journal, self.blobs)

    def append(self, entries):
        tx = uuid.uuid4().hex
        blobs = [self.blobs.put(entry.payload()) for entry in entries]
        allocated = self.journal.begin(tx, blobs)
        for entry in entries:
            if not valid(entry, self.keys):
                self.journal.event("aborted", tx, [])
                raise ReleaseError("entry signature rejected")
        self.journal.event("committed", tx, allocated)
        return allocated

    def incremental(self, entries):
        self.append(entries)
        return self.checkpoints.seal()

    def recover(self):
        # Recovery rebuilds from committed events but retains allocator state.
        checkpoint = self.checkpoints.seal()
        return checkpoint
