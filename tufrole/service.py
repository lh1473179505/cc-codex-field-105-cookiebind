import uuid
from pathlib import Path

from .keys import KeyEpochs
from .snapshots import Snapshots
from .transactions import Transactions
from .verifier import Verifier, VerificationError


class RoleService:
    def __init__(self, root):
        self.root = Path(root)
        self.epochs = KeyEpochs(self.root / "keys")
        self.transactions = Transactions(self.root / "transactions")
        self.snapshots = Snapshots(self.root)
        self.verifier = Verifier(self.epochs)

    def begin(self, role):
        epoch, _ = self.epochs.current()
        tx = uuid.uuid4().hex
        self.transactions.create(tx, epoch, role)
        return tx

    def commit(self, tx):
        record = self.transactions.load(tx)
        role = self.verifier.from_record(record["role"])
        self.verifier.verify(role, record["epoch"])
        roles = self.snapshots.all()
        roles[role.name] = role.record()
        self.snapshots.write(roles)
        self.transactions.mark(tx, "committed")

    def rotate(self, epoch, keys, revoked):
        self.epochs.rotate(epoch, keys, revoked)

    def recover(self, tx):
        record = self.transactions.load(tx)
        if record["state"] == "prepared":
            self.commit(tx)
        return self.snapshots.legacy()
